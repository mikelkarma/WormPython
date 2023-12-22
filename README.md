# Python Code Overview
Esse e um codigo python3 criado no meu tempo livre, ele e um tipo de worm que tenta se espalhar pela rede.
Obs: Ele está incompleto. Sinta-se livre para fazer o que bem entender, mas lembrando que a responsabilidade é sua.

## Functionalities

### 1. Autocópia e Registro de Inicialização:
O script copia a si mesmo para a pasta de inicialização do Windows e adiciona uma entrada de registro para garantir que seja executado na inicialização.

### 2. Coleta de Informações do Sistema:
O código coleta informações detalhadas sobre o sistema em que está sendo executado, incluindo informações sobre a CPU, memória, discos, rede, etc.

### 3. Execução Remota de Comandos:
O script permite a execução remota de comandos em sistemas infectados.

### 4. Worm
O script tenta se espalhar para pastas compartilhadas, servidores FTP, SSH, Telnet e bancos de dados MySQL usando credenciais padrão.
Quando ele adentra em um servidor mysql ele faz uma copia do banco de dados para c:\\mysql

# Aviso de Responsabilidade: Utilização do Código Worm
Este script Python foi desenvolvido por Mik e é disponibilizado como um codigo aberto. 
Ao escolher usar este script, o usuário aceita total responsabilidade pelos resultados
e possíveis impactos derivados da sua utilização.
