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

This prompt tells you that you have to generate a pair of keys and a master password. Once you type the command `init`, you will be guided through that process, everything is clearly explained.
     
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