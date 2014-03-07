#!/usr/bin/python
import sys
import argparse
import json

from genpiepie.genpiepie import sign
from genpiepie.genpiepie import verify_signature
from genpiepie.genpiepie import gen_certificate
from genpiepie.genpiepie import verify_certificate

def main():
    parser = argparse.ArgumentParser(description="Generate certificate")

    parser.add_argument('-p', '--privatekey', help='The private key file used to sign certificate', required=True)
    parser.add_argument('-pub', '--publickey', help='The public key file used to verify certificate', required=True)
    parser.add_argument('-o', '--output', help='The file to store certificate', required=True)

    args = parser.parse_args()

    # test sign certificate
    cert = 'cerificate'
    signature = sign(cert, args.privatekey)

    # test certificate signature
    if verify_signature(cert, args.publickey, signature):
        print('valid signature')
    else:
        print('invalid signature')
        
    ## generate certificate
    certificate = gen_certificate(args.privatekey)
    
    ## export certificate
    ## TODO base64 encoding
    cert_file = open(args.output, 'wb')
    cert_file.write(json.dumps(certificate))
    cert_file.close()

    ## verify certificate

    cert_file = open(args.output, 'r')
    scertificate = cert_file.read()
    certificate = json.loads(scertificate)

    if verify_certificate(certificate, args.privatekey):
        print('valid certificate')
    else:
        print('invalid certificate')
        

if __name__ == "__main__":
    sys.exit(main())
