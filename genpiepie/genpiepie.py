#!/usr/bin/python
import logging as log
import string
import base64
import json

import Crypto.Hash.SHA256 as sha
import Crypto.PublicKey.RSA as rsa
import Crypto.Cipher.PKCS1_OAEP as pkcs
import Crypto.Random.random as rand
import Crypto.Signature.PKCS1_v1_5 as pkcs_sgn


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

    with open(priv_output, 'wb') as private_key:
        private_key.write(key.exportKey('PEM'))

    with open(pub_output, 'wb') as public_key:
        public_key.write(key.publickey().exportKey("PEM"))


def get_key_length(privatekey):
    """ Returns the length of a private key

    Keywords arguments:
    privatekey      -- The file containing the private key
    """
    try:
        priv_key = open(privatekey).read()
    except Exception as err:
        log.error("[get_key_length] {}".format(err))
    else:
        rsa_key = rsa.importKey(priv_key)
        return rsa_key.size()


def gen_masterpwd(length=128, public=None):
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

    if public is not None:
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
        finally:
            pub_file.close()

    else:
        return master


def gen_pwd(user, web, masterpwd, strip=6, private=None, masteronfile=False, version=-1):
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

    if private is not None:
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
        log.error("[gen_pwd] The master password you gave is too short")
        return

    if len(masterpwd) < 10:
        log.warning("[gen_pwd] The master password you gave is short, please consider using a longer one")

    sym1 = masterpwd[-2]
    sym2 = masterpwd[-1]
    masterpwd = masterpwd[:-2]

    h = sha.new()
    h.update(masterpwd.encode('utf-8'))
    h.update(user.encode('utf-8'))
    h.update('@'.encode('utf-8'))
    h.update(web.encode('utf-8'))

    # This allows us to generate multiple passwords with the same couples
    if version >= 0:
        h.update(masterpwd[version % len(masterpwd)])

    digest = h.hexdigest()

    return "{}{}{}{}{}".format(
        digest[:strip].upper(),
        sym1,
        digest[
        int(len(digest) / 2) - int(strip / 2):
        int(len(digest) / 2) + int(strip / 2)
        ],
        sym2,
        digest[-strip:].lower()
    )

def sign(sdata, private):

    try:
        priv_file = open(private, 'r')

    except Exception as err:
        log.error("[sign] {}".format(err))


    priv_key = priv_file.read()
    key = rsa.importKey(priv_key)
    priv_file.close()

    h = sha.new(sdata)
    signer = pkcs_sgn.new(key)
    signature = signer.sign(h)

    return base64.b64encode(signature)

def verify_signature(sdata, public, signature):
    
    try:
        pub_file = open(public, 'r')

    except Exception as err:
        log.error("[verify_signature] {}".format(err))


    pub_key = pub_file.read()
    key = rsa.importKey(pub_key)
    pub_file.close()
    
    h = sha.new(sdata)

    verifier = pkcs_sgn.new(key)
    signature = base64.b64decode(signature)

    if verifier.verify(h, signature):
        return True
    else:
        return False

def gen_certificate(private):
    
    # subject
    subject = 'some subject'
    
    # validity
    notbefore = 'Feb  1 10:00:00 2014 GMT'
    notafter  = 'Jul  2 12:00:00 2014 GMT'
    
    data = { 
        'subject': subject,
        'validity': {
            'not_before': notbefore,
            'not_after': notafter
            }
        }

    sdata = json.dumps(data)

    signature = sign(sdata, private)
    
    certificate = {
        'data': data,
        'signature': signature
        }

    return certificate

def verify_certificate(certificate, public):
    
    data = certificate['data']

    sdata = json.dumps(data)

    signature = certificate['signature']
    
    if verify_signature(sdata, public, signature):
        return True
    else:
        return False
