#!/usr/bin/env python3

import sys
import re
import argparse
import os.path
import pyperclip as pyclip
import json
import dataset
import Crypto.Hash.SHA as sha

from genpiepie.genpiepie import *


class fmt:
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class DataManager():
    def __init__(self, filename):

        try:
            self.db = dataset.connect("sqlite:///{}".format(filename))
            self.table = self.db.get_table('couples', primary_id='id', primary_type='String')
        except Exception as err:
            print("Problem while initializing the database: {}",err)
            raise Exception("Unrecoverable error")

    def storeInDB(self, user, website, version=-1):
        """" Stores the couple User/Website in the database

        Uses an sha on user@website as an index
        """
        h = sha.new()
        h.update("{}@{}".format(user,website).encode('utf-8'))

        self.table.upsert(
            dict(
                id = h.hexdigest(),
                user = user.strip(),
                web  = website.strip(),
                ver  = version
            ), keys=['id', 'user', 'web', 'ver'])

    def listContent(self):
        """ Returns a list containing all the database
        """
        # return [self.db[id] for id in self.db]
        return self.table.all()

    def find(self, hash):
        return self.table.find_one(id = hash)

class Manager():
    def __init__(self, workingdir=None, privatekeyfile=None, publickeyfile=None, masterpwdfile=None):
        self.workingdir = workingdir
        self.privatekey = None
        self.publickey = None
        self.masterpwd = None
        self.masterpwdIsAFile = True
        self.couples = None

        if workingdir is not None:
            if os.path.isdir(workingdir):
                self.workingdir = workingdir
            else:
                raise Exception("{} is not a valid directory".format(workingdir))
        else:
            gppath = os.path.expanduser('~/.genpiepie')
            if not os.path.isdir(gppath) :
                os.mkdir(gppath)

            self.workingdir = gppath

        print(self.workingdir)

        if os.path.exists("{}/conf.json".format(self.workingdir)):
            jconf = dict()
            with open("{}/conf.json".format(self.workingdir), 'r') as jc:
                jconf = json.load(jc)

            if privatekeyfile is None and 'priv' in jconf:
                privatekeyfile = jconf['priv']

            if publickeyfile is None and 'pub' in jconf:
                publickeyfile = jconf['pub']

            if masterpwdfile is None and 'mpwd' in jconf:
                masterpwdfile = ""
                self.masterpwd = jconf['mpwd']
                self.masterpwdIsAFile = False

        if privatekeyfile is None and \
                        publickeyfile is None and \
                        masterpwdfile is None:
            print("""
No RSA pair of keys was provided, nor a master password. The manager cannot be used without!
You can use the {red}{bold}security{end} command to either provide the location of the files,
or generate them. You can also use the {red}{bold}init{end} command to be guided through this
process.
            """.format(bold=fmt.BOLD, end=fmt.END, red=fmt.RED))

        elif privatekeyfile is not None and \
                        publickeyfile is not None and \
                        masterpwdfile is None:
            print("""
No master password was provided. You will have to generate one through the command {red}{bold}security{end}.
            """.format(bold=fmt.BOLD, end=fmt.END, red=fmt.RED))

            privatekeyfile.replace('~', os.path.expanduser('~'))
            publickeyfile.replace('~', os.path.expanduser('~'))
            if os.path.isfile(privatekeyfile) and \
                    os.path.isfile(publickeyfile):
                self.privatekey = privatekeyfile
                self.publickey = publickeyfile

        elif privatekeyfile is not None and \
                        publickeyfile is not None and \
                        masterpwdfile is not None:

            privatekeyfile.replace('~', os.path.expanduser('~'))
            publickeyfile.replace('~', os.path.expanduser('~'))

            if self.masterpwdIsAFile:
                masterpwdfile.replace('~', os.path.expanduser('~'))

            if os.path.isfile(privatekeyfile):
                self.privatekey = privatekeyfile
            else:
                raise Exception("The provided private key file is not a regular file")

            if os.path.isfile(publickeyfile):
                self.publickey = publickeyfile
            else:
                raise Exception("The provided public key file is not a regular file")

            if self.masterpwdIsAFile:
                if os.path.isfile(masterpwdfile):
                    with open(masterpwdfile, 'r') as m:
                        self.masterpwd = m.read()
                else:
                    raise Exception("The provided master password file is not a regular file")


        #everything is ready! Create the list of couples if it does not exist
        self.couples = "{}/couples.db".format(self.workingdir)
        try:
            self.db = DataManager(self.couples)
        except Exception as err:
            print(err)
            sys.exit(0)




    @property
    def isInitialized(self):
        return self.privatekey is not None and \
               self.publickey is not None and \
               self.masterpwd is not None

    def showHelp(self, command=None):
        if command is None or command == '':
            print("""
There are two available commands:
* {red}{bold}list{end}        or {red}{bold}l{end}    -- Lists available user/website couples
* {red}{bold}find{end}        or {red}{bold}f{end}    -- Finds a couple user/website
* {red}{bold}gen{end}         or {red}{bold}g{end}    -- Generate a password for a user/website couple
* {red}{bold}clean{end}       or {red}{bold}c{end}    -- Cleans the clipboard (from the copied password)
* [NYI]{red}{bold}security{end}       -- Generate a pair of keys and/or a master password.
                               Provide a pair of keys and/or a master password.
* {red}{bold}init{end}                -- Same as {red}{bold}security{end}, except that it is
               guided (no options to provide, just follow the guide)
* {red}{bold}help{end}        or {red}{bold}h{end}    -- Shows this help
* {red}{bold}quit{end}        or {red}{bold}q{end}    -- Exits the manager

If you do not already have a pair of keys and a master password, you have
to generate them first before being able to use the other commands.
You can use the command {red}{bold}init{end} to go through that process.

Type "help <command name>" to see the specific help for this command
            """.format(bold=fmt.BOLD, end=fmt.END, red=fmt.RED))
        elif command == "gen":
            print("""
Generates a password for a couple of user/website, requires a pair of keys
and a master password. If you do not have them please use the `init` command
to generate them.

You can use either of the following options with the `gen` command:

* {red}{bold}new{end} user website      --  Generate a password for the couple user:website.
                            If the couple user:website is in the saved list, this
                            option is equivalent to "show the password for this
                            couple", otherwise it will add that couple to the
                            list and generate the password.
* {red}{bold}regen{end} user website    --  Regenerate the password for the selected couple.
                            The couple user:website has to be in the list, if it
                            is not this option is equivalent to `new`.

If you give no option (neither new, nor regen), the option {red}{bold}new{end} will be considered.

Example:
{cyan}gen new myUberuser myWebiste.com{end}
            """.format(bold=fmt.BOLD, end=fmt.END, red=fmt.RED, cyan=fmt.CYAN))
        elif command == "list":
            print("""
Lists the available couple of user/password
            """)

    def initialize(self):
        print("""
You will be guided through the process of the creation of a pair of RSA keys and a master
password file that will be used to generate the passwords. If you intended to provide
the files rather than generate them, please use the {red}{bold}security{end} command,
give an empty file name to return to the main screen.

The name of RSA pair of keys will be prefixed with a name that you will provide first, then
we generate a master password and save it under a name that you provide. You can chose the
length of both the RSA key and the master password.
        """.format(bold=fmt.BOLD, end=fmt.END, red=fmt.RED, cyan=fmt.CYAN))

        jconf = dict()
        if self.privatekey is None and \
                        self.publickey is None:

            keysprefix = ""
            while keysprefix == "":
                keysprefix = input("RSA keys' name prefix: ")
                if keysprefix == "":
                    print("Please give at least one character for the prefix.")

            keylength = 256
            while keylength < 1024 or keylength % 8 != 0:
                keylength = input("RSA key length larger or equal to 1024 [default = 2048]: ")

                if keylength == "":
                    keylength = 2048
                else:
                    try:
                        keylength = int(keylength)
                    except Exception as err:
                        print("Please provide a correct length value: {}".format(err))
                        continue

                if keylength % 8 != 0:
                    print("The length of the key has to be a multiple of 8, we suggest 2048 or 4096 bits keys.")

            keysprefix = "{}/{}".format(self.workingdir,keysprefix)
            gen_key(output=keysprefix, length=keylength)

            #we do not need to store their values in memory, only the file name is required
            self.privatekey = "{}_priv.pem".format(keysprefix)
            self.publickey = "{}_pub.pem".format(keysprefix)

            jconf['priv'] = self.privatekey
            jconf['pub'] = self.publickey
        else:
            keylength = get_key_length(self.privatekey)

        mpwdFile = input("Name of the master password file: [mpw] ")
        if mpwdFile == "":
            mpwdFile = "mpw"

        mpwdLength = 5
        while mpwdLength < 10 and mpwdLength < (keylength / 8 - 2):
            mpwdLength = input("Master password length larger or equal to 10 [default = 128]: ")

            if mpwdLength == "":
                mpwdLength = 128
            else:
                try:
                    mpwdLength = int(mpwdLength)
                except Exception as err:
                    print("Please provide a correct length value: {}".format(err))
                    continue

            if mpwdLength > (keylength / 8 - 2):
                print("The length of the master password is limited to {}, this is linked to the length of the RSA key"
                      .format(keylength / 8 - 2))

        self.masterpwd = gen_masterpwd(length=mpwdLength, public=self.publickey)

        mpwdFile = "{}/{}".format(self.workingdir,mpwdFile)
        with open(mpwdFile, 'wb') as mpwfe:
            mpwfe.write(self.masterpwd)
            mpwfe.write(b'\n')
            mpwfe.close()

        # the encrypted master password can be stored in memory with no issue
        self.masterpwd = self.masterpwd.decode('ascii')
        self.masterpwdIsAFile = False

        jconf['mpwd'] = self.masterpwd

        with open("{}/conf.json".format(self.workingdir), "w") as jc:
            json.dump(jconf, jc)


    def generate(self, options=None):
        if not self.isInitialized:
            print("The manager is not initialized, use the help command to see how to do it.")
            return

        options = options.split()

        if options[0] == "new" and len(options) == 3:
            cmd = "new"
        elif options[0] == "regen" and len(options) == 3:
            cmd = "regen"
        elif len(options) > 2:
            print("Too many options, please provide a user and a website.")
            return
        elif len(options) < 2:
            print("Too few options, please provide a user and a website.")
            return
        else:
            cmd = "new"

        if cmd == "new":
            pwd = gen_pwd(options[0].strip(), options[1].strip(), self.masterpwd, private=self.privatekey)

            copyto = input("Copy to clipboard? [y/N] ")
            if copyto.lower() == "y" or copyto.lower() == "yes":
                pyclip.setcb(pwd)
            else:
                print("Your password is: {}".format(pwd))

            self.db.storeInDB(options[0],options[1])
                

        else:
            print("Not Yet Implemented")


    def list(self):
        for cpl in self.db.listContent():
            print("User   : {}".format(cpl['user']))
            print("Website: {}".format(cpl['web']))
            print("--------")

    def find(self, string):
        ids = []
        i = 0
        for cpl in self.db.listContent():
            if string in cpl['user'] or string in cpl['web']:
                print("Couple", i + 1)
                print("User   : {}".format(cpl['user']))
                print("Website: {}".format(cpl['web']))
                ids.append(cpl['id'])
                i += 1

        if i > 0:
            yn = 1
            try: 
                inp = input("Which couple do you want to generate the password for? [{}] ".format(yn))
                if inp != '':
                    yn = int(inp)
            except Exception as err:
                print("Problem with your input", err)
                return
                    
            if yn > 0 and yn <= len(ids):
                cpl = self.db.find(ids[yn - 1])
                pwd = gen_pwd(cpl['user'], cpl['web'], self.masterpwd, private=self.privatekey)

                copyto = input("Copy to clipboard? [y/N] ")
                if copyto.lower() == "y" or copyto.lower() == "yes":
                    pyclip.setcb(pwd)
                else:
                    print("Your password is: {}".format(pwd))
                

    def run(self):
        command = "init"
        print("Type exit to stop the shell")
        pattern = re.compile("^\s*(\w+)\s*(.*)$")
        while True:
            command = input("> ")
            try:
                cmd = re.findall(pattern, command)
            except Exception as err:
                print("Error: Unable to parse your command")
                print(err)
                continue

            if len(cmd) < 1:
                print("""
Please type a command, or {bold}{red}exit{end} to closethe manager.
Use {bold}{red}help{end} to see how to use the manager.
                    """.format(bold=fmt.BOLD, end=fmt.END, red=fmt.RED))
                continue
            else:
                cmd = cmd[0]

            if cmd[0] == "help" or cmd[0] == "h":
                if len(cmd) > 1:
                    self.showHelp(cmd[1].strip())
                else:
                    self.showHelp()

            elif cmd[0] == "init":
                self.initialize()

            elif cmd[0] == "gen" or cmd[0] == "g":
                if len(cmd) > 1 and cmd[1] != '':
                    self.generate(cmd[1].strip())
                else:
                    self.generate()

            elif cmd[0] == "list" or cmd[0] == "l":
                self.list()

            elif cmd[0] == "find" or cmd[0] == "f":
                if len(cmd) > 1:
                    self.find(cmd[1].strip())
                else:
                    self.find('')

            elif cmd[0] == "clean" or cmd[0] == "c":
                pyclip.setcb("the password was here")

            elif cmd[0] == "exit" or cmd[0] == "q":
                break
            else:
                print("Not Implemented Yet")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Generate passwords")

    parser.add_argument('-w', '--workingdir',
                        help='The directory where the master password file and the list of user/websites will be stored in')
    parser.add_argument('-p', '--privatekey', help='The private key file used to decrypt the master password')
    parser.add_argument('-u', '--publickey', help='The pulic key file used to encrypt the master password')
    parser.add_argument('-m', '--masterpwd', help='The master password file')

    args = parser.parse_args()

    if args.privatekey is None and args.masterpwd is not None:
        print("We will be unable to decrypt the master password without a private key")
        return 1

    if args.publickey is None and args.masterpwd is None and args.privatekey is not None:
        print("We will be unable to encrypt the generated master password without a public key")
        return 2

    if args.publickey is not None and args.privatekey is None:
        print("We will be unable to generate any password without the private key")
        return 3

    manager = Manager(workingdir=args.workingdir, privatekeyfile=args.privatekey, publickeyfile=args.publickey,
                      masterpwdfile=args.masterpwd)

    manager.run()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
