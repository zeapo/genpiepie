#!/usr/bin/python
import sys, argparse
from getpass import getpass
from genpiepie import gen_pwd


def main(argv=None):
    parser = argparse.ArgumentParser(description="Generate passwords")

    parser.add_argument('-u', '--user', help='The username', required=True)
    parser.add_argument('-w', '--website', help='The website', required=True)

    args = parser.parse_args()

    key = getpass('Input the KEY: ')

    if sys.version_info >= (3,0):
        sym1 = str(input('Input the first symbol: '))
        sym2 = str(input('Input the first symbol: '))
    else:
        sym1 = str(raw_input('Input the first symbol: '))
        sym2 = str(raw_input('Input the first symbol: '))

    print(gen_pwd(args.user, args.website, sym1, sym2, key))

if __name__ == "__main__":
    sys.exit(main(sys.argv))
