#!/usr/bin/python

import Crypto.Hash.SHA256 as sha
import sys
import getpass

def gen_pwd(user,web,sym1=None,sym2=None,key=None,strip=4):
    """ Generates a password for the couple user/website

    Keywords arguments:
    user    -- The username
    web     -- The website
    sym1    -- The first symbol to be used as separator
    sym2    -- The second symbol to be used as separator
    key     -- The key to be used to gen the password
    strip   -- The number of characters to be used in each slice of the password (default 4)
    """
    if not key:
        key = getpass.getpass('Input the KEY: ')


    # Python 3.x uses input() to read from keyboard, 2.x uses it to eval
    # we'd like it to be to read from keyboard
    try:
        input = raw_input
    except NameError:
        pass

    if not sym1:
        sym1 = str(input('Input the first symbol: ')).encode('utf-8')

    if not sym2:
        sym2 = str(input('Input the first symbol: ')).encode('utf-8')

    h = sha.new()
    h.update(key.encode('utf-8'))
    h.update(user.encode('utf-8'))
    h.update(u'@')
    h.update(web.encode('utf-8'))
    digest = h.hexdigest()
    return "{}{}{}{}{}".format(
            digest[:strip].upper(),
            sym1,
            digest[
                    int(len(digest)/2) - int(strip/2):
                    int(len(digest)/2) + int(strip/2)
                   ],
            sym2,
            digest[-strip:].lower()
            )

def main(argv=None):
    if len(argv) < 3:
        print("Usage: {} username website".format(argv[0]))
        return 1
    username = argv[1]
    website = argv[2]
    print(gen_pwd(username, website))

if __name__ == "__main__":
    sys.exit(main(sys.argv))
