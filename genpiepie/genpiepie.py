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

    items = string.printable.replace(' ', '')
    master = []

    for i in range(length):
        master.append(items[rand.randrange(0, len(items))])

    symbols = "".join(rand.sample(string.punctuation, 2))
    master.append(symbols)

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
            try:
                ciph = cipher.encrypt(master.encode('utf-8'))
            except Exception as err:
                log.error("[gen_masterpwd] Error while encrypting the master password : {}".format(err))
            else:
                return base64.b64encode(ciph)

    else:
        return master

def gen_pwd(user,web,masterpwd,strip=6,private=None,masteronfile=False):
    """ Generates a password for the couple user/website

    Keywords arguments:
    user            -- The username
    web             -- The website
    masterpwd       -- The master password to be used to gen the password,
                        if masteronfile is true, then masterpwd is the file
                        containing the master password
    strip           -- The number of characters to be used in each slice of
                        the password (default 4)
    private         -- The private key used to decrypt an encrypted masterpwd
                        encoded in b64 (default None)
    masteronfile    -- Means that the masterpwd is on a file (default False)
    """

    if masteronfile:
        masterpwd = open(masterpwd, 'r').read()

    if private != None:
        try:
            priv_file = open(private, 'r')

        except Exception as err:
            log.error("[gen_pwd] {}".format(err))

        else:
            priv_key = priv_file.read()
            rsa_key = rsa.importKey(priv_key)
            cipher = pkcs.new(rsa_key)
            masterpwd = base64.b64decode(masterpwd)
            masterpwd = cipher.decrypt(masterpwd).decode('utf-8')
            priv_file.close()

    if len(masterpwd) < 3:
        logging.error("[gen_pwd] The master password you gave is too short")
        return

    if len(masterpwd) < 10:
        logging.warning("[gen_pwd] The master password you gave is short, please consider using a longer one")

    sym1 = masterpwd[-2]
    sym2 = masterpwd[-1]
    masterpwd = masterpwd[:-2]

    h = sha.new()
    h.update(masterpwd.encode('utf-8'))
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
