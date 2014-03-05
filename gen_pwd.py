#!/usr/bin/python
import sys, argparse
from getpass import getpass
from genpiepie import gen_pwd


def main(argv=None):
    parser = argparse.ArgumentParser(description="Generate passwords")

    parser.add_argument('-u', '--user', help='The username', required=True)
    parser.add_argument('-w', '--website', help='The website', required=True)
    parser.add_argument('-m', '--masterpwd', help='The master password file')
    parser.add_argument('-p', '--privatekey', help='The private key file used to decrypt the master password')

    args = parser.parse_args()

    onfile = False

    if args.masterpwd:
        onfile = True
    else: 
        masterpwd = getpass('Input the master password: ')

    if sys.version_info >= (3,0):
        sym1 = str(input('Input the first symbol: '))
        sym2 = str(input('Input the first symbol: '))
    else:
        sym1 = str(raw_input('Input the first symbol: '))
        sym2 = str(raw_input('Input the first symbol: '))

    print(gen_pwd(args.user, args.website, sym1, sym2, masterpwd))

if __name__ == "__main__":
    sys.exit(main(sys.argv))
