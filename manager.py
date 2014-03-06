import sys
import re


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


class Manager():
    def __init__(self, workingdir="./", privateKeyFile=None, publicKeyFile=None, masterKeyPasswordFile=None):
        self.workingdir = workingdir

    def showHelp(self, command=None):
        if command is None or command == '':
            print("""
            There are two available commands:
            * {red}{bold}list{end}      -- Lists available user/website couples
            * {red}{bold}gen{end}       -- Generate a password for a user/website couple
            * {red}{bold}security{end}  -- Generate a pair of keys and/or a master password

            If you do not already have a pair of keys and a master password, you have
            to generate them first before being able to use the other commands.
            You can use the command `init` to go through that process.

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

            Both these options accept

            Example:
            {cyan}gen new myUberuser myWebiste.com{end}
            """.format(bold=fmt.BOLD, end=fmt.END, red=fmt.RED, cyan=fmt.CYAN))
        elif command == "list":
            print("""
            Lists the available couple of user/password
            """)


    def run(self):
        command = "init"
        print("Type exit to stop the shell")
        pattern = re.compile("^(\w+)\s?(\w+)?$")
        while command != "exit":
            command = input("> ")
            try:
                cmd = re.findall(pattern, command)
            except Exception as err:
                print("Error: Unable to parse your command")
                print(err)
                continue

            if len(cmd) < 1:
                print("""
            Please type a command, or {bold}{red}exit{end} to close the manager.
            Use {bold}{red}help{end} to see how to use the manager.
                """
                      .format(bold=fmt.BOLD, end=fmt.END, red=fmt.RED))
                continue
            else:
                cmd = cmd[0]

            if cmd[0] == "help":
                if len(cmd) > 1:
                    self.showHelp(cmd[1])
                else:
                    self.showHelp()


def main(argv=None):
    manager = Manager()

    manager.run()


if __name__ == "__main__":
    sys.exit(main(sys.argv))