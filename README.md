genpiepie
=========

Simple password generator in python

Generating passwords
=========
The basic idea is to combine the couple `username`/`website` with a
`master_password` and two symbols to generate a unique password. This latter
can be regenerated at each time, using `gen_pwd()`, as long as we know the key
and the symbols. We offer a simple script to use this function easily:

    usage: gen_pwd.py -u USER -w WEBSITE

    Generate passwords
        -u USER, --user USER  The username
        -w WEBSITE, --website WEBSITE The website

Combining multiple couples of usernames and websites with a single couple of
`master_password` and symbols, one has only to remember the later to generate
any password he wants again and again. However, this `master_password` is a
security point of failure, hence a long and hard to find one is a must. 

To achieve that, we think that a randomly generated `key` encrypted using an
RSA key is the answer. This is where `gen_masterpwd()` and `gen_keys()` come
to the rescue. We offer a simple script that combines both of them and generates
a set of keys and encrypts a random `masterkey` using the public key generated:

    usage: gen_keys.py [--output OUTPUT] [--length LENGTH] [--masterkey MASTERKEY]

    Generate RSA keys and a masterkey encrypted with the publickey

    optional arguments:
    --output OUTPUT         The prefix of private keys
    --length LENGTH         The length of the key
    --masterkey MASTERKEY   A randomly generated masterkey, encoded in b64


