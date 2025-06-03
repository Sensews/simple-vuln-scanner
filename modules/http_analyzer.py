"""
Módulo HTTP Analyzer
===================

Responsável por analisar serviços HTTP/HTTPS em busca de headers de segurança,
informações de servidor e possíveis vulnerabilidades básicas.
"""

import requests
import ssl
import socket
from urllib.parse import urljoin, urlparse
from datetime import datetime
from .utils import logger


class HTTPAnalyzer:
    """Analisador de serviços HTTP/HTTPS"""
    
    def __init__(self, target, timeout=10):
        """
        Inicializa o analisador HTTP
        
        Args:
            target (str): IP ou hostname do alvo
            timeout (int): Timeout para requisições
        """
        self.target = target
        self.timeout = timeout
        self.session = requests.Session()
        self.session.timeout = timeout
        
        # Headers para parecer um navegador real
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Desabilitar verificação SSL para teste
        self.session.verify = False
        requests.packages.urllib3.disable_warnings()
    
    def analyze(self):
        """
        Executa análise completa HTTP/HTTPS
        
        Returns:
            dict: Resultados da análise
        """
        results = {
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'http_info': {},
            'https_info': {},
            'security_headers': {},
            'vulnerabilities': [],
            'recommendations': []
        }
        
        # Testar HTTP (porta 80)
        http_url = f"http://{self.target}"
        results['http_info'] = self.analyze_url(http_url)
        
        # Testar HTTPS (porta 443)
        https_url = f"https://{self.target}"
        results['https_info'] = self.analyze_url(https_url)
        
        # Analisar headers de segurança
        if results['http_info'].get('accessible') or results['https_info'].get('accessible'):
            results['security_headers'] = self.analyze_security_headers(results)
            results['vulnerabilities'] = self.identify_vulnerabilities(results)
            results['recommendations'] = self.generate_recommendations(results)
        
        return results
    
    def analyze_url(self, url):
        """
        Analisa uma URL específica
        
        Args:
            url (str): URL para analisar
            
        Returns:
            dict: Informações da URL
        """
        logger.info(f"Analisando: {url}")
        
        info = {
            'url': url,
            'accessible': False,
            'status_code': None,
            'headers': {},
            'server': None,
            'technologies': [],
            'ssl_info': {},
            'response_time': None,
            'content_length': None,
            'error': None
        }
        
        try:
            start_time = datetime.now()
            response = self.session.get(url, allow_redirects=True)
            end_time = datetime.now()
            
            info['accessible'] = True
            info['status_code'] = response.status_code
            info['headers'] = dict(response.headers)
            info['response_time'] = (end_time - start_time).total_seconds()
            info['content_length'] = len(response.content)
            
            # Extrair informações do servidor
            info['server'] = response.headers.get('Server', 'Desconhecido')
            
            # Identificar tecnologias
            info['technologies'] = self.identify_technologies(response)
            
            # Analisar SSL se for HTTPS
            if url.startswith('https'):
                info['ssl_info'] = self.analyze_ssl(self.target, 443)
            
            logger.success(f"URL acessível: {url} (Status: {response.status_code})")
            
        except requests.exceptions.SSLError as e:
            info['error'] = f"Erro SSL: {str(e)}"
            logger.warning(f"Erro SSL em {url}: {str(e)}")
            
        except requests.exceptions.ConnectionError as e:
            info['error'] = f"Erro de conexão: {str(e)}"
            logger.debug(f"Não foi possível conectar a {url}")
            
        except requests.exceptions.Timeout as e:
            info['error'] = f"Timeout: {str(e)}"
            logger.warning(f"Timeout ao acessar {url}")
            
        except Exception as e:
            info['error'] = f"Erro inesperado: {str(e)}"
            logger.error(f"Erro ao analisar {url}: {str(e)}")
        
        return info
    
    def identify_technologies(self, response):
        """
        Identifica tecnologias web baseadas em headers e conteúdo
        
        Args:
            response: Objeto response do requests
            
        Returns:
            list: Lista de tecnologias identificadas
        """
        technologies = []
        headers = response.headers
        content = response.text.lower()
        
        # Identificar servidor web
        server = headers.get('Server', '').lower()
        if 'apache' in server:
            technologies.append(f"Apache {server.split('/')[1] if '/' in server else ''}")
        elif 'nginx' in server:
            technologies.append(f"Nginx {server.split('/')[1] if '/' in server else ''}")
        elif 'iis' in server:
            technologies.append(f"IIS {server.split('/')[1] if '/' in server else ''}")
        
        # Identificar linguagens/frameworks
        if 'x-powered-by' in headers:
            powered_by = headers['x-powered-by']
            technologies.append(f"Powered by: {powered_by}")
        
        # Identificar através do conteúdo
        if 'wordpress' in content:
            technologies.append('WordPress')
        if 'joomla' in content:
            technologies.append('Joomla')
        if 'drupal' in content:
            technologies.append('Drupal')
        if 'jquery' in content:
            technologies.append('jQuery')
        if 'bootstrap' in content:
            technologies.append('Bootstrap')
        
        return technologies
    
    def analyze_ssl(self, hostname, port):
        """
        Analisa informações SSL/TLS
        
        Args:
            hostname (str): Nome do host
            port (int): Porta SSL
            
        Returns:
            dict: Informações SSL
        """
        ssl_info = {}
        
        try:
            # Obter certificado
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    ssl_info = {
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'version': cert.get('version'),
                        'serial_number': cert.get('serialNumber'),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter'),
                        'cipher_suite': cipher[0] if cipher else None,
                        'tls_version': cipher[1] if cipher else None,
                        'key_length': cipher[2] if cipher else None
                    }
        
        except Exception as e:
            ssl_info['error'] = str(e)
        
        return ssl_info
    
    def analyze_security_headers(self, results):
        """
        Analisa headers de segurança
        
        Args:
            results (dict): Resultados da análise
            
        Returns:
            dict: Análise dos headers de segurança
        """
        security_headers = {
            'present': [],
            'missing': [],
            'analysis': {}
        }
        
        # Headers importantes de segurança
        important_headers = {
            'Strict-Transport-Security': 'HSTS - Força uso de HTTPS',
            'X-Content-Type-Options': 'Previne MIME type sniffing',
            'X-Frame-Options': 'Previne clickjacking',
            'X-XSS-Protection': 'Proteção contra XSS (legado)',
            'Content-Security-Policy': 'CSP - Controla recursos carregados',
            'Referrer-Policy': 'Controla informações de referrer',
            'Permissions-Policy': 'Controla APIs do navegador'
        }
        
        # Verificar em ambos HTTP e HTTPS
        all_headers = {}
        if results['http_info'].get('headers'):
            all_headers.update(results['http_info']['headers'])
        if results['https_info'].get('headers'):
            all_headers.update(results['https_info']['headers'])
        
        # Analisar cada header
        for header, description in important_headers.items():
            if header in all_headers:
                security_headers['present'].append({
                    'header': header,
                    'value': all_headers[header],
                    'description': description
                })
            else:
                security_headers['missing'].append({
                    'header': header,
                    'description': description,
                    'impact': 'Possível vulnerabilidade de segurança'
                })
        
        return security_headers
    
    def identify_vulnerabilities(self, results):
        """
        Identifica possíveis vulnerabilidades
        
        Args:
            results (dict): Resultados da análise
            
        Returns:
            list: Lista de vulnerabilidades identificadas
        """
        vulnerabilities = []
        
        # Verificar se HTTP está ativo sem redirecionamento para HTTPS
        if (results['http_info'].get('accessible') and 
            results['http_info'].get('status_code') == 200 and
            not results['https_info'].get('accessible')):
            
            vulnerabilities.append({
                'type': 'Insecure Protocol',
                'severity': 'Medium',
                'description': 'Site acessível apenas via HTTP (sem criptografia)',
                'recommendation': 'Implementar HTTPS e redirecionar HTTP para HTTPS'
            })
        
        # Verificar headers de segurança ausentes
        missing_headers = results.get('security_headers', {}).get('missing', [])
        if len(missing_headers) > 3:
            vulnerabilities.append({
                'type': 'Missing Security Headers',
                'severity': 'Medium',
                'description': f'{len(missing_headers)} headers de segurança importantes ausentes',
                'recommendation': 'Implementar headers de segurança apropriados'
            })
        
        # Verificar informações do servidor expostas
        for info_key in ['http_info', 'https_info']:
            if results[info_key].get('server'):
                server = results[info_key]['server']
                if any(version in server.lower() for version in ['apache/2.2', 'nginx/1.0', 'iis/6.0']):
                    vulnerabilities.append({
                        'type': 'Information Disclosure',
                        'severity': 'Low',
                        'description': f'Versão do servidor exposta: {server}',
                        'recommendation': 'Ocultar versão do servidor web'
                    })
        
        # Verificar certificado SSL
        ssl_info = results.get('https_info', {}).get('ssl_info', {})
        if ssl_info and 'error' in ssl_info:
            vulnerabilities.append({
                'type': 'SSL/TLS Issue',
                'severity': 'High',
                'description': f'Problema com certificado SSL: {ssl_info["error"]}',
                'recommendation': 'Corrigir configuração SSL/TLS'
            })
        
        return vulnerabilities
    
    def generate_recommendations(self, results):
        """
        Gera recomendações de segurança
        
        Args:
            results (dict): Resultados da análise
            
        Returns:
            list: Lista de recomendações
        """
        recommendations = []
        
        # Recomendações baseadas em vulnerabilidades
        vulnerabilities = results.get('vulnerabilities', [])
        if vulnerabilities:
            recommendations.append({
                'category': 'Security',
                'priority': 'High',
                'title': 'Corrigir Vulnerabilidades Identificadas',
                'description': f'Foram encontradas {len(vulnerabilities)} possíveis vulnerabilidades que devem ser corrigidas.'
            })
        
        # Recomendações para headers de segurança
        missing_headers = results.get('security_headers', {}).get('missing', [])
        if missing_headers:
            recommendations.append({
                'category': 'Headers',
                'priority': 'Medium',
                'title': 'Implementar Headers de Segurança',
                'description': f'Implementar {len(missing_headers)} headers de segurança ausentes para melhorar a proteção.'
            })
        
        # Recomendação geral
        recommendations.append({
            'category': 'General',
            'priority': 'Medium',
            'title': 'Auditoria de Segurança Regular',
            'description': 'Realizar auditorias regulares de segurança e manter softwares atualizados.'
        })
        
        return recommendations
