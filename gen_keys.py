#!/usr/bin/python
import sys, argparse
from genpiepie import gen_key

def main(argv=None):
    parser = argparse.ArgumentParser(description="Generate RSA keys")

    parser.add_argument('--output', help='The output file name', default='privkey.pem')
    parser.add_argument('--length', help='The length of the key', default=2048)

    args = parser.parse_args()
    print(args)

    gen_key(args.output, args.length)

if __name__ == "__main__":
    sys.exit(main(sys.argv))
