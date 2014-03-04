#!/usr/bin/python

import sys

from Crypto.PublicKey import RSA

def gen_key(n=2048):
    
    if int(n) < 1024:
        print("[gen_key] insecure key size")
        return 

    print("[dbg][gen_key] genrate RSA key size {}".format(n))
    key = RSA.generate(2048)
    f = open('test_privkey.pem','w')
    f.write(key.exportKey('PEM'))
    f.close()

# test
def main(argv=None):

    if len(argv) < 2:
        gen_key()
    else:
        if argv[1] == '-h':
            print("Usage: {} [keysize]".format(argv[0]))
        else:
            gen_key(argv[1])



if __name__ == "__main__":
    sys.exit(main(sys.argv))
