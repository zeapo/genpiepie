#!/usr/bin/python
import Crypto.Hash.SHA256 as sha
import Crypto.PublicKey.RSA as rsa
import Crypto.Cipher.PKCS1_OAEP as pkcs
import Crypto.Random.random as rand
import logging as log
import string, base64

def gen_key(output='mykey', length=2048):
    """ Generates a couple of RSA private / public keys

    Keywords arguments:
    output      -- The prefix used for naming the keys
    length      -- The length of the key
    """
    if int(length) < 1024:
        log.error("[gen_key] insecure key size")
        return 

    log.debug("[gen_key] genrate RSA key size {}".format(length))

    try:
        key = rsa.generate(int(length))
    except Exception as err:
        log.error("[gen_key] {}".format(err))
        return

    priv_output = "{}_priv.pem".format(output)
    pub_output = "{}_pub.pem".format(output)

    private_key = open(priv_output, 'wb')
    private_key.write(key.exportKey('PEM'))
    private_key.close()

    public_key = open(pub_output, 'wb')
    public_key.write(key.publickey().exportKey("PEM"))
    public_key.close()

def gen_masterpwd(length=128,public=None):
    """ Generates a random masterkey password and optionaly encrypt it

    Keywords arguments:
    length      -- The length of the masterkey password we want (default 128)
    public      -- The public key file to use to encrypt the masterkey password (default None)
    """

    items = string.ascii_letters
    master = []

    for i in range(length):
        master.append(items[rand.randrange(0, len(items))])

    master = "".join(master)

    if public != None:
        try:
            pub_file = open(public, 'r')

        except Exception as err:
            log.error("[gen_masterpwd] {}".format(err))

        else:
            pub_key = pub_file.read()
            rsa_key = rsa.importKey(pub_key)
            cipher = pkcs.new(rsa_key)
            return base64.b64encode(cipher.encrypt(master.encode('utf-8')))

    else:
        return master

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
