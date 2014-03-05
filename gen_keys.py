#!/usr/bin/python
import sys, argparse
from genpiepie import gen_key, gen_masterpwd

def main(argv=None):
    parser = argparse.ArgumentParser(description="Generate RSA keys and a masterkey encrypted with the publickey")

    parser.add_argument('--output', help='The prefix of private keys', default='key')
    parser.add_argument('--length', help='The length of the key', default=2048)
    parser.add_argument('--masterkey', help='A randomly generated masterkey, encoded in b64')

    args = parser.parse_args()

    gen_key(args.output, args.length)

    if args.masterkey != None:
        key = gen_masterpwd(public="{}_pub.pem".format(args.output))
        try:
            master_key = open(args.masterkey, 'wb')

        except Exception as err:
            print("There was a problem: {}", err)
            print("Here is your key anyway : {}".format(key))

        else:
            master_key.write(key)
            master_key.write(b'\n')
            master_key.close()

if __name__ == "__main__":
    sys.exit(main(sys.argv))