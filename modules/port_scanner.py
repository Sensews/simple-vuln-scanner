"""
Módulo Port Scanner
==================

Responsável por realizar o escaneamento de portas TCP em um alvo específico.
Utiliza sockets Python para verificar conectividade e identifica serviços comuns.
"""

import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from .utils import logger


class PortScanner:
    """Scanner de portas TCP"""
    
    # Dicionário de serviços comuns por porta
    COMMON_SERVICES = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        135: 'RPC',
        139: 'NetBIOS',
        143: 'IMAP',
        443: 'HTTPS',
        993: 'IMAPS',
        995: 'POP3S',
        1723: 'PPTP',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC',
        8080: 'HTTP-Alt'
    }
    
    def __init__(self, target, ports, timeout=3, max_threads=100):
        """
        Inicializa o scanner de portas
        
        Args:
            target (str): IP ou hostname do alvo
            ports (str): String com portas separadas por vírgula
            timeout (int): Timeout para conexão em segundos
            max_threads (int): Número máximo de threads
        """
        self.target = target
        self.timeout = timeout
        self.max_threads = max_threads
        self.open_ports = []
        self.closed_ports = []
        
        # Processar lista de portas
        try:
            if '-' in ports:
                # Suporte para range (ex: 1-1000)
                start, end = map(int, ports.split('-'))
                self.ports = list(range(start, end + 1))
            else:
                # Lista de portas separadas por vírgula
                self.ports = [int(p.strip()) for p in ports.split(',')]
        except ValueError:
            raise ValueError("Formato de portas inválido. Use: 80,443 ou 1-1000")
    
    def scan_port(self, port):
        """
        Escaneia uma porta específica
        
        Args:
            port (int): Número da porta
            
        Returns:
            dict: Informações da porta escaneada
        """
        try:
            # Resolver hostname para IP se necessário
            target_ip = socket.gethostbyname(self.target)
            
            # Criar socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Tentar conectar
            result = sock.connect_ex((target_ip, port))
            sock.close()
            
            if result == 0:
                # Porta aberta
                service = self.COMMON_SERVICES.get(port, 'Desconhecido')
                
                # Tentar identificar banner/serviço
                banner = self.grab_banner(target_ip, port)
                
                port_info = {
                    'port': port,
                    'status': 'open',
                    'service': service,
                    'banner': banner
                }
                
                logger.info(f"Porta {port} aberta ({service})")
                return port_info
            else:
                # Porta fechada
                return {
                    'port': port,
                    'status': 'closed'
                }
                
        except socket.gaierror:
            logger.error(f"Erro ao resolver hostname: {self.target}")
            return None
        except Exception as e:
            logger.debug(f"Erro ao escanear porta {port}: {str(e)}")
            return {
                'port': port,
                'status': 'error',
                'error': str(e)
            }
    
    def grab_banner(self, target_ip, port, timeout=2):
        """
        Tenta capturar banner do serviço
        
        Args:
            target_ip (str): IP do alvo
            port (int): Porta do serviço
            timeout (int): Timeout para captura
            
        Returns:
            str: Banner capturado ou None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target_ip, port))
            
            # Enviar requisição básica dependendo do serviço
            if port == 80:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n")
            elif port == 443:
                # Para HTTPS seria necessário SSL, então apenas tentamos receber
                pass
            elif port in [21, 22, 23, 25]:
                # FTP, SSH, Telnet, SMTP geralmente enviam banner automaticamente
                pass
            
            # Tentar receber banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner[:100] if banner else None  # Limitar tamanho do banner
            
        except:
            return None
    
    def scan(self):
        """
        Executa o escaneamento de todas as portas
        
        Returns:
            dict: Resultados do escaneamento
        """
        logger.info(f"Iniciando escaneamento de {len(self.ports)} portas em {self.target}")
        start_time = datetime.now()
        
        # Escaneamento com threads
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Submeter todas as tarefas
            future_to_port = {
                executor.submit(self.scan_port, port): port 
                for port in self.ports
            }
            
            # Coletar resultados
            for future in as_completed(future_to_port):
                result = future.result()
                if result:
                    if result['status'] == 'open':
                        self.open_ports.append(result)
                    elif result['status'] == 'closed':
                        self.closed_ports.append(result)
        
        end_time = datetime.now()
        scan_duration = (end_time - start_time).total_seconds()
        
        # Organizar resultados
        results = {
            'target': self.target,
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'duration': scan_duration,
            'total_ports': len(self.ports),
            'open_ports': sorted(self.open_ports, key=lambda x: x['port']),
            'closed_ports_count': len(self.closed_ports),
            'summary': {
                'open_count': len(self.open_ports),
                'closed_count': len(self.closed_ports),
                'total_scanned': len(self.ports)
            }
        }
        
        logger.info(f"Escaneamento concluído em {scan_duration:.2f} segundos")
        return results
    
    def get_service_vulnerabilities(self, port, service, banner=None):
        """
        Identifica possíveis vulnerabilidades baseadas no serviço
        
        Args:
            port (int): Número da porta
            service (str): Nome do serviço
            banner (str): Banner capturado
            
        Returns:
            list: Lista de possíveis vulnerabilidades
        """
        vulnerabilities = []
        
        # Verificações básicas baseadas em portas/serviços
        if port == 23:  # Telnet
            vulnerabilities.append({
                'type': 'Insecure Protocol',
                'severity': 'High',
                'description': 'Telnet transmite dados em texto plano',
                'recommendation': 'Use SSH em vez de Telnet'
            })
        
        if port == 21:  # FTP
            vulnerabilities.append({
                'type': 'Potentially Insecure',
                'severity': 'Medium',
                'description': 'FTP pode transmitir credenciais em texto plano',
                'recommendation': 'Considere usar SFTP ou FTPS'
            })
        
        if port in [135, 139]:  # RPC, NetBIOS
            vulnerabilities.append({
                'type': 'Information Disclosure',
                'severity': 'Medium',
                'description': 'Serviços Windows que podem vazar informações',
                'recommendation': 'Desabilite se não necessário'
            })
        
        # Verificações baseadas em banner
        if banner:
            banner_lower = banner.lower()
            
            # Versões antigas/vulneráveis comuns
            if any(old_version in banner_lower for old_version in [
                'apache/2.2', 'apache/2.0', 'nginx/1.0', 'nginx/1.1',
                'openssh_5', 'openssh_6', 'microsoft-iis/6.0'
            ]):
                vulnerabilities.append({
                    'type': 'Outdated Software',
                    'severity': 'High',
                    'description': f'Software possivelmente desatualizado: {banner[:50]}',
                    'recommendation': 'Atualize para a versão mais recente'
                })
        
        return vulnerabilities
