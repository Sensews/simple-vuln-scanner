"""
Módulo Utils
============

Utilitários compartilhados entre os módulos do scanner de vulnerabilidades.
Inclui logging, validação de alvos e outras funções auxiliares.
"""

import re
import socket
import ipaddress
from colorama import Fore, Style, init

# Inicializar colorama para Windows
init(autoreset=True)


class Logger:
    """Sistema de logging customizado com cores"""
    
    def __init__(self):
        self.verbose = False
    
    def set_verbose(self, verbose):
        """Define modo verbose"""
        self.verbose = verbose
    
    def info(self, message):
        """Log de informação"""
        print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} {message}")
    
    def success(self, message):
        """Log de sucesso"""
        print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} {message}")
    
    def warning(self, message):
        """Log de aviso"""
        print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} {message}")
    
    def error(self, message):
        """Log de erro"""
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {message}")
    
    def debug(self, message):
        """Log de debug (apenas se verbose estiver ativo)"""
        if self.verbose:
            print(f"{Fore.MAGENTA}[DEBUG]{Style.RESET_ALL} {message}")


# Instância global do logger
logger = Logger()


def validate_target(target):
    """
    Valida se o alvo é um IP ou hostname válido
    
    Args:
        target (str): IP ou hostname para validar
        
    Returns:
        bool: True se válido, False caso contrário
    """
    # Tentar validar como IP
    try:
        ipaddress.ip_address(target)
        logger.debug(f"Alvo {target} validado como endereço IP")
        return True
    except ValueError:
        pass
    
    # Tentar validar como hostname/domínio
    if is_valid_hostname(target):
        try:
            # Tentar resolver o hostname
            socket.gethostbyname(target)
            logger.debug(f"Alvo {target} validado como hostname")
            return True
        except socket.gaierror:
            logger.error(f"Não foi possível resolver o hostname: {target}")
            return False
    
    return False


def is_valid_hostname(hostname):
    """
    Verifica se uma string é um hostname válido
    
    Args:
        hostname (str): String para validar
        
    Returns:
        bool: True se for um hostname válido
    """
    if len(hostname) > 253:
        return False
    
    # Remover ponto final se presente
    if hostname.endswith('.'):
        hostname = hostname[:-1]
    
    # Regex para validar hostname
    hostname_regex = re.compile(
        r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$'
    )
    
    # Verificar cada parte separada por ponto
    parts = hostname.split('.')
    if len(parts) < 1:
        return False
    
    for part in parts:
        if not hostname_regex.match(part):
            return False
    
    return True


def is_port_open(host, port, timeout=3):
    """
    Verifica se uma porta específica está aberta
    
    Args:
        host (str): IP ou hostname
        port (int): Número da porta
        timeout (int): Timeout em segundos
        
    Returns:
        bool: True se a porta estiver aberta
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False


def format_bytes(bytes_value):
    """
    Formata bytes em formato legível
    
    Args:
        bytes_value (int): Valor em bytes
        
    Returns:
        str: Valor formatado (ex: "1.5 KB")
    """
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} TB"


def format_duration(seconds):
    """
    Formata duração em formato legível
    
    Args:
        seconds (float): Duração em segundos
        
    Returns:
        str: Duração formatada (ex: "1m 30s")
    """
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = seconds % 60
        return f"{minutes}m {secs:.0f}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"


def get_severity_color(severity):
    """
    Retorna cor baseada na severidade
    
    Args:
        severity (str): Nível de severidade
        
    Returns:
        str: Código de cor colorama
    """
    severity_colors = {
        'low': Fore.GREEN,
        'medium': Fore.YELLOW,
        'high': Fore.RED,
        'critical': Fore.MAGENTA
    }
    return severity_colors.get(severity.lower(), Fore.WHITE)


def parse_port_range(port_string):
    """
    Converte string de portas em lista de inteiros
    
    Args:
        port_string (str): String com portas (ex: "80,443" ou "1-1000")
        
    Returns:
        list: Lista de números de porta
    """
    ports = []
    
    for part in port_string.split(','):
        part = part.strip()
        if '-' in part:
            # Range de portas
            try:
                start, end = map(int, part.split('-'))
                if start <= end and 1 <= start <= 65535 and 1 <= end <= 65535:
                    ports.extend(range(start, end + 1))
                else:
                    raise ValueError(f"Range de portas inválido: {part}")
            except ValueError:
                raise ValueError(f"Range de portas inválido: {part}")
        else:
            # Porta individual
            try:
                port = int(part)
                if 1 <= port <= 65535:
                    ports.append(port)
                else:
                    raise ValueError(f"Porta inválida: {port}")
            except ValueError:
                raise ValueError(f"Porta inválida: {part}")
    
    return sorted(list(set(ports)))  # Remove duplicatas e ordena


def create_progress_bar(current, total, bar_length=50):
    """
    Cria uma barra de progresso em texto
    
    Args:
        current (int): Progresso atual
        total (int): Total de itens
        bar_length (int): Comprimento da barra
        
    Returns:
        str: Barra de progresso formatada
    """
    if total == 0:
        return "[" + "=" * bar_length + "] 100%"
    
    progress = current / total
    filled_length = int(bar_length * progress)
    bar = "=" * filled_length + "-" * (bar_length - filled_length)
    percentage = progress * 100
    
    return f"[{bar}] {percentage:.1f}% ({current}/{total})"


def sanitize_filename(filename):
    """
    Remove caracteres inválidos de um nome de arquivo
    
    Args:
        filename (str): Nome do arquivo
        
    Returns:
        str: Nome sanitizado
    """
    # Caracteres inválidos no Windows
    invalid_chars = '<>:"/\\|?*'
    
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    
    # Remover espaços extras e pontos no final
    filename = filename.strip(' .')
    
    return filename


def get_common_ports():
    """
    Retorna lista das portas mais comuns para escaneamento
    
    Returns:
        list: Lista de portas comuns
    """
    return [
        21,    # FTP
        22,    # SSH
        23,    # Telnet
        25,    # SMTP
        53,    # DNS
        80,    # HTTP
        110,   # POP3
        135,   # RPC
        139,   # NetBIOS
        143,   # IMAP
        443,   # HTTPS
        993,   # IMAPS
        995,   # POP3S
        1723,  # PPTP
        3306,  # MySQL
        3389,  # RDP
        5432,  # PostgreSQL
        5900,  # VNC
        8080   # HTTP-Alt
    ]


def get_port_description(port):
    """
    Retorna descrição de uma porta
    
    Args:
        port (int): Número da porta
        
    Returns:
        str: Descrição do serviço
    """
    descriptions = {
        21: "FTP - File Transfer Protocol",
        22: "SSH - Secure Shell",
        23: "Telnet - Terminal emulation",
        25: "SMTP - Simple Mail Transfer Protocol",
        53: "DNS - Domain Name System",
        80: "HTTP - HyperText Transfer Protocol",
        110: "POP3 - Post Office Protocol v3",
        135: "RPC - Remote Procedure Call",
        139: "NetBIOS - Network Basic Input/Output System",
        143: "IMAP - Internet Message Access Protocol",
        443: "HTTPS - HTTP Secure",
        993: "IMAPS - IMAP over SSL",
        995: "POP3S - POP3 over SSL",
        1723: "PPTP - Point-to-Point Tunneling Protocol",
        3306: "MySQL Database",
        3389: "RDP - Remote Desktop Protocol",
        5432: "PostgreSQL Database",
        5900: "VNC - Virtual Network Computing",
        8080: "HTTP Alternative port"
    }
    
    return descriptions.get(port, f"Porta {port} - Serviço desconhecido")
