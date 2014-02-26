#!/usr/bin/python

import Crypto.Hash.SHA256 as sha
import sys
import getpass

def gen_pwd(user,web,key=None):
    if not key:
        key = getpass.getpass('Input the KEY: ')

    h = sha.new()
    h.update(key.encode('utf-8'))
    h.update(user.encode('utf-8'))
    h.update(u'@')
    h.update(web.encode('utf-8'))
    digest = h.hexdigest()
    return "{}!{}@{}".format( digest[:4],digest[8:12],digest[-4:] )

def main(argv=None):
    if len(argv) < 3:
        print("Usage: {} username website".format(argv[0]))
        return 1
    username = argv[1]
    website = argv[2]
    print(gen_pwd(username, website))

if __name__ == "__main__":
    sys.exit(main(sys.argv))
