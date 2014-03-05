#!/usr/bin/python
import sys
import argparse
from getpass import getpass

from genpiepie.genpiepie import gen_pwd


def main():
    parser = argparse.ArgumentParser(description="Generate passwords")

    parser.add_argument('-u', '--user', help='The username', required=True)
    parser.add_argument('-w', '--website', help='The website', required=True)
    parser.add_argument('-m', '--masterpwd', help='The master password file')
    parser.add_argument('-p', '--privatekey', help='The private key file used to decrypt the master password')

    args = parser.parse_args()

    onfile = False

    if args.masterpwd:
        onfile = True
        masterpwd = args.masterpwd
    else:
        masterpwd = getpass('Input the master password: ')

    print(gen_pwd(args.user, args.website, masterpwd, strip=4,
                  private=args.privatekey, masteronfile=onfile))


if __name__ == "__main__":
    sys.exit(main())
