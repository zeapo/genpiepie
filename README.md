genpiepie
=========

Simple password manager in python

Generating passwords
=========
The basic idea is to combine the couple `username`/`website` with a
`master_password` and two symbols to generate a unique password. To do that, **genpiepie** offers three key functions
- `gen_key` generates a pair of RSA keys with user specified length and passphrase
- `gen_masterpwd` generates a random master password and encrypt it using a public key so that only the user can decrypt it
- `gen_pwd` generates a password for a couple of **username** and **website** using the **master password** generated earlier

Using these key functions, we have built a password manager that stores only the couples of username/website and gives the ability to generate, for each couple, a unique password. If the password is compromized, we  offer also the possibility for the user to regenerate a new one for the same couple and keep track of these changes.

# The manager #

Running the `manager.py` script the first time will prompt you with a shell-like interface:

    No RSA pair of keys was provided, nor a master password. The manager cannot be used without!
    You can use the init command to be guided through the process of creating them.

    Type exit to stop the shell
    > 

This prompt tells you that you have to generate a pair of keys and a master password. Once you type the command `init`, you will be guided through that process, everything is clearly explained. Here is an example:
     
    > init

    You will be guided through the process of the creation of a pair of RSA keys and a master
    password file that will be used to generate the passwords. If you intended to provide
    the files rather than generate them, please use the security command,
    give an empty file name to return to the main screen.

    The name of RSA pair of keys will be prefixed with a name that you will provide first, then
    we generate a master password and save it under a name that you provide. You can chose the
    length of both the RSA key and the master password.

    RSA keys' name prefix: mykey
    RSA key length larger or equal to 1024 [default = 2048]: 4096
    Do you want to use a passphrase? [y/N] y
    Passphrase: 
    Name of the master password file: [mpw] mymaster
    Master password length larger or equal to 10 [default = 128]: 
    > 

When you run the manager for the first time, a directory `.genpiepie` is created in your home directory. After the initialization, it will be populated with the different files.

    $ ls ~/.genpiepie 
    conf.json  couples.db  mykey_priv.pem  mykey_pub.pem  mymaster

The pair of keys is named (as we told the `init` command) `mykey_priv.pem` and `mykey_pub.pem`. The encrypted master password is stored in `mymaster`.

Two other files are created, the configuration file `conf.json`:

    {
        "priv": "/home/user/.genpiepie/mykey_priv.pem"
        "pub": "/home/user/.genpiepie/mykey_pub.pem",
        "pass": true,
        "mpwd": "PS+8pFXT1U4z/FGuoFC1V28pGX/hpSO7ygCQES8Yurq3LxlF/nbDP34tkfsO3VzbetjcYfkT/G/D1Hbi9qy3dvUC9IYpT2HmypLX4Rw4PBwzDikWmX3ekTu8FVfFATyWCPxV6BFnCRwuym+8z81B/8GIfR3gjrvQHQmt6POafaHkPMqiuCj8WE6kOayDDxw9JEZEi/Xe6WZHCG9NkzUqQDhRLwW8211iTOQU+2DabJdh5JbQh6ytqyyfo7rkkYou2sLxtxPDLMUzOWNmmCIlFtaNbHyWPjYxgjyGqv42F/3i8uEOS9FtEWmS0Y+xzRxC9NC6u79rrgum7IHKSwh7nAo9an/2eHio2i59VXYXx8wR/96aCcVdW7KE6SekO/DNQBE2IUVFnfM9swXBSdvYpmBagiWgBn+AEfZG7aUCK0sckSwsHfHZcnNzP4QsO+ANzZpGiiF32xD4ToH5CHZ7d90ebFaNZkr3xwAdoErUDqOh3IR84he1fiunyGTFSqMFtf4pRAbV9a6zHu2EoFweNObqD/6c2bWxtJ7Qv0dtfDOyhqJNQ0Gtd+Ng6Qvf8k3k7qo0rfkPxzshdJTT+JZiMeDDPJSEGAy9iOTh9kFBvLCNsnsWdGjFil5dRBofwP8yR3v7r7WRMEXlEdrsRa6PThQfbU1F4+xWLsXb83aOC2I=",
    }

The `priv` and `pub` keys contain the path to the private and public
keys respectively. The `pass` if set to `true` means that the private
key is passphrase protected (note: this is only for convenience, it
will be removed in future versions). Finally, the `mpwd` contains the
encrypted master password, this is in fact the content of the master
password file. The choice of duplicating the master password is only
for convenience, the user needs only to store the `conf.json` and the
database `couples.db` on his computer, the keys can be in different locations.


Once we have everything set, we can start generating the passwords. There is a quite verbose `help` command to understand the different commands:

    > help

    * list        or l    -- Lists available user/website couples
    * find        or f    -- Finds a couple user/website
    * gen         or g    -- Generate a password for a user/website couple
    * regen       or r    -- Generates a new version of the password for a user/website couple
    * delete      or d    -- Deletes a user/website couple
    * clean       or c    -- Cleans the clipboard (from the copied password)
    * init                -- Initialization wizard, helps to create the RSA keys
                   and master password, just follow the guide
    * help        or h    -- Shows this help
    * quit        or q    -- Exits the manager

    If you do not already have a pair of keys and a master password, you have
    to generate them first before being able to use the other commands.
    You can use the command init to go through that process.

To generate a first password we use the command `gen` or `g` for lazy fellows :)

    > g myuser@mywebsite.com github.com
    passphrase: 
    Copy to clipboard? [y/N] N
    Your password is: 0F0F77{1d897d"ce45cf

Here we generated a password for the username *myuser@mywebsite.com* and website *github.com*. Notice that calling these couples *username*/*website* does not restrict the usage to application passwords.

The manager asks for a pass phrase if the private key requires one. We need the private key to decrypt the master password that will help us to generate the password. Next, the manager asks if we want to copy the password to the clipboard so that we paste it directly into the login form, if we say *no* (default option), the password is shown to us. We discuss later the simple generator we are using.

The couple of username and website will is now stored in the database, if we want to list the content of the database we can use the command `list` or `l`:

    > l
    User   : myuser@mywebsite.com
    Website: github.com
    --------

Notice how we provide only the username and the website as the
password is not stored in the database. If we want to see the password
we have two ways to do that. First, we can use the `gen` command
again, we will obtain the same result as earlier usage of the `gen`
command and the couple stays unique in the database (no new entry is
created). Second, we can use the command `find` (or `f`) that search through
the available couples and propose to generate the password:

    > f github
    Couple 1
    User   : myuser@mywebsite.com
    Website: github.com
    Which couple do you want to generate the password for? (empty for none) 
    > f myuser
    Couple 1
    User   : myuser@mywebsite.com
    Website: github.com
    Which couple do you want to generate the password for? (empty for none) 1
    passphrase: 
    Copy to clipboard? [y/N] N
    Your password is: 0F0F77{1d897d"ce45cf

Notice that it searches on both the usernames and websites and you can see (generate) the password for whichever couple you find.

Suppose that you wanted to put into the clipboard your password, we provide a simple way to clean it using the `clean` or `c` command that will put into the clipboard the sentence *the password was here*. 