# Background

Some JWT libraries are vulnerable to a known attack which changes
the type of a JWT from an asymmetric (e.g. RS256) to a symmetric
one (e.g. HS256), as described
[here](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)

This script will change the algorithm of a JWT to a symmetric one and re-sign
it with a given public key, varying the line length of the PEM data. If the
remote server is vulnerable it will try to verify the signature using its
public key, as usual, but now using a symmetric algorithm, and hopefully
succeed for one of the generated signatures. See also
[here](https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2019/january/jwt-attack-walk-through/)

# Usage

```
usage: jwt_resign_asym_to_sym.py [-h] [-j FILE] [-k FILE] [-f ALGO] [-t ALGO]
                                 [-n]

Re-sign a JWT with a public key, changing its type from RS265 to HS256. Unless
disabled, it will re-sign it once for each possible line length of the public
key (starting at the length of the header line).

optional arguments:
  -h, --help            show this help message and exit
  -j FILE, --jwt-file FILE
                        File containing the JWT. (default: jwt.txt)
  -k FILE, --key-file FILE
                        File containing the public PEM key. (default: key.pem)
  -f ALGO, --from-algorithm ALGO
                        Original algorithm of the JWT. (default: RS256)
  -t ALGO, --to-algorithm ALGO
                        Convert JWT to this algorithm. (default: HS256)
  -n, --no-vary         Sign only once with the exact key given. (default:
                        False)
```

# Getting the public key 

## From the SSL certificate

Many sites use a single private/public key pair and that's the one
in their SSL certificate, so try this, replacing `{server}` with the
domain name and `{HTTPS` port} with e.g. 443:

```bash
$ echo QUIT | openssl s_client -connect "{server}:{HTTPS port}" -showcerts 2> /dev/null > cert.pem
```

then extract the public key from it:

```bash
$ openssl x509 -in cert.pem -pubkey -noout > key.pem
```

## From the JWKS

1. From the OpenID conf

    Servers which use OpenID keep the configuration in a well known
    location. If the OpenID endpoint is e.g.
    `http://example.com/service/auth/`, then try:
    
    ```
    $ curl http://example.com/service/auth/.well-known/openid-configuration
    ```
    
    then look for the `jwks_uri` parameter. This points to the resource
    containing the public keys and their IDs.

2. From the OpenID conf

    If the server doesn't use OpenID, it may still provide a JWKS under the
    following URL
    
    ```
    $ curl http://example.com/.well-known/jwks.json
    ```

If you found the JWKS JSON configuration, then fecth it and choose the key
with the same `kid` as the `kid` in the JWT headers:

```
$ cut -d. -f1 <<<"{JWT here}" | base64 -d
```

After you have the JWT keys configuration (from the JWKS endpoint), and

1. you get the PEM certificate (`x5c` parameter), but no public key,
   save the value of the certificate to a file (`cert.pem`), adding
   the header and footer lines as follows:

```
-----BEGIN CERTIFICATE-----
{value of x5c parameter}
-----END CERTIFICATE-----
```

   then extract the public key from it:

```
$ openssl x509 -in cert.pem -pubkey -noout > key.pem
```

2. you don't get the PEM certificate (`x5c` paramter), but instead
   have the public key as a combination of a modulus (`n` parameter)
   and exponent (`e` parameter), do:

```
$ res=$(sed 's/-/+/g;s/_/\//g' <<<"${base64 of modulus}"); n=$(( 4 - (${#res} % 4) )); echo -n "${res}"; printf "%0.s=" $(seq 1 $n);
```

   in order to replace the URI-safe charset of Base64 with the traditional
   charset of Base64 (see
   [this](https://stackoverflow.com/a/13195218/8457586)), and to pad it
   with `=` as necessary. Then use
   [this](https://superdry.apphb.com/tools/online-rsa-key-converter)
   online tool to generate a PEM public key from the modulus and exponent. 

# TO DO

* Support for signing with a key in DER format
