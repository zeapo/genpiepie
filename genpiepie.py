#!/usr/bin/python
import Crypto.Hash.SHA256 as sha
import Crypto.PublicKey.RSA as rsa

def gen_key(output='privkey.pem', n=2048):
    
    if int(n) < 1024:
        print("[gen_key] insecure key size")
        return 

    print("[dbg][gen_key] genrate RSA key size {}".format(n))
    key = rsa.generate(2048)
    f = open(output,'w')
    f.write(key.exportKey('PEM'))
    f.close()

def gen_pwd(user,web,sym1,sym2,key,strip=4):
    """ Generates a password for the couple user/website

    Keywords arguments:
    user    -- The username
    web     -- The website
    sym1    -- The first symbol to be used as separator
    sym2    -- The second symbol to be used as separator
    key     -- The key to be used to gen the password
    strip   -- The number of characters to be used in each slice of the password (default 4)
    """

    h = sha.new()
    h.update(key.encode('utf-8'))
    h.update(user.encode('utf-8'))
    h.update('@'.encode('utf-8'))
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
