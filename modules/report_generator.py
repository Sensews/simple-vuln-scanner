"""
Módulo Report Generator
======================

Responsável por gerar relatórios em diferentes formatos (TXT, HTML, JSON)
baseados nos resultados do escaneamento de vulnerabilidades.
"""

import json
import os
from datetime import datetime
from .utils import logger


class ReportGenerator:
    """Gerador de relatórios de vulnerabilidades"""
    
    def __init__(self, scan_results):
        """
        Inicializa o gerador de relatórios
        
        Args:
            scan_results (dict): Resultados do escaneamento
        """
        self.results = scan_results
        self.reports_dir = "reports"
        
        # Criar diretório de relatórios se não existir
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)
    
    def generate(self, format_type, filename):
        """
        Gera relatório no formato especificado
        
        Args:
            format_type (str): Formato do relatório (txt, html, json)
            filename (str): Nome base do arquivo (sem extensão)
            
        Returns:
            str: Caminho do arquivo gerado
        """
        if format_type == 'txt':
            return self.generate_txt_report(filename)
        elif format_type == 'html':
            return self.generate_html_report(filename)
        elif format_type == 'json':
            return self.generate_json_report(filename)
        else:
            raise ValueError(f"Formato não suportado: {format_type}")
    
    def generate_txt_report(self, filename):
        """
        Gera relatório em formato texto
        
        Args:
            filename (str): Nome base do arquivo
            
        Returns:
            str: Caminho do arquivo gerado
        """
        filepath = os.path.join(self.reports_dir, f"{filename}.txt")
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(self._get_txt_header())
            f.write(self._get_txt_summary())
            
            if self.results.get('port_scan'):
                f.write(self._get_txt_port_results())
            
            if self.results.get('http_analysis'):
                f.write(self._get_txt_http_results())
            
            f.write(self._get_txt_footer())
        
        logger.info(f"Relatório TXT gerado: {filepath}")
        return filepath
    
    def generate_html_report(self, filename):
        """
        Gera relatório em formato HTML
        
        Args:
            filename (str): Nome base do arquivo
            
        Returns:
            str: Caminho do arquivo gerado
        """
        filepath = os.path.join(self.reports_dir, f"{filename}.html")
        
        html_content = self._get_html_template()
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"Relatório HTML gerado: {filepath}")
        return filepath
    
    def generate_json_report(self, filename):
        """
        Gera relatório em formato JSON
        
        Args:
            filename (str): Nome base do arquivo
            
        Returns:
            str: Caminho do arquivo gerado
        """
        filepath = os.path.join(self.reports_dir, f"{filename}.json")
        
        # Adicionar metadados ao JSON
        json_data = {
            "scan_metadata": {
                "generated_at": datetime.now().isoformat(),
                "scanner_version": "1.0",
                "report_format": "json"
            },
            "scan_results": self.results
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Relatório JSON gerado: {filepath}")
        return filepath
    
    def _get_txt_header(self):
        """Retorna cabeçalho do relatório TXT"""
        return f"""
{'='*80}
                    RELATÓRIO DE ESCANEAMENTO DE VULNERABILIDADES
{'='*80}

Alvo: {self.results['target']}
Data/Hora: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}
Scanner: Vulnerability Scanner v1.0

{'='*80}

"""
    
    def _get_txt_summary(self):
        """Retorna resumo do escaneamento"""
        summary = "\n[RESUMO EXECUTIVO]\n" + "-"*50 + "\n"
        
        if self.results.get('port_scan'):
            open_ports = len(self.results['port_scan']['open_ports'])
            total_ports = self.results['port_scan']['total_ports']
            summary += f"• Portas escaneadas: {total_ports}\n"
            summary += f"• Portas abertas: {open_ports}\n"
        
        if self.results.get('http_analysis'):
            vulns = len(self.results['http_analysis']['vulnerabilities'])
            summary += f"• Vulnerabilidades HTTP encontradas: {vulns}\n"
        
        summary += "\n"
        return summary
    
    def _get_txt_port_results(self):
        """Retorna resultados do scanner de portas em formato TXT"""
        port_scan = self.results['port_scan']
        txt = "\n[RESULTADOS DO SCANNER DE PORTAS]\n" + "-"*50 + "\n"
        
        txt += f"Duração do escaneamento: {port_scan['duration']:.2f} segundos\n\n"
        
        if port_scan['open_ports']:
            txt += "PORTAS ABERTAS:\n"
            for port_info in port_scan['open_ports']:
                txt += f"  • Porta {port_info['port']}: {port_info['service']}\n"
                if port_info.get('banner'):
                    txt += f"    Banner: {port_info['banner'][:100]}...\n"
        else:
            txt += "Nenhuma porta aberta encontrada.\n"
        
        txt += "\n"
        return txt
    
    def _get_txt_http_results(self):
        """Retorna resultados da análise HTTP em formato TXT"""
        http_analysis = self.results['http_analysis']
        txt = "\n[RESULTADOS DA ANÁLISE HTTP]\n" + "-"*50 + "\n"
        
        # Informações HTTP
        if http_analysis['http_info'].get('accessible'):
            txt += f"HTTP (porta 80): Acessível (Status: {http_analysis['http_info']['status_code']})\n"
            txt += f"  Servidor: {http_analysis['http_info'].get('server', 'Desconhecido')}\n"
        else:
            txt += "HTTP (porta 80): Não acessível\n"
        
        # Informações HTTPS
        if http_analysis['https_info'].get('accessible'):
            txt += f"HTTPS (porta 443): Acessível (Status: {http_analysis['https_info']['status_code']})\n"
            txt += f"  Servidor: {http_analysis['https_info'].get('server', 'Desconhecido')}\n"
        else:
            txt += "HTTPS (porta 443): Não acessível\n"
        
        # Headers de segurança
        txt += "\nHEADERS DE SEGURANÇA:\n"
        security_headers = http_analysis.get('security_headers', {})
        
        if security_headers.get('present'):
            txt += "  Presentes:\n"
            for header in security_headers['present']:
                txt += f"    ✓ {header['header']}\n"
        
        if security_headers.get('missing'):
            txt += "  Ausentes:\n"
            for header in security_headers['missing']:
                txt += f"    ✗ {header['header']} - {header['description']}\n"
        
        # Vulnerabilidades
        if http_analysis.get('vulnerabilities'):
            txt += "\nVULNERABILIDADES IDENTIFICADAS:\n"
            for vuln in http_analysis['vulnerabilities']:
                txt += f"  • {vuln['type']} (Severidade: {vuln['severity']})\n"
                txt += f"    Descrição: {vuln['description']}\n"
                txt += f"    Recomendação: {vuln['recommendation']}\n\n"
        
        return txt
    
    def _get_txt_footer(self):
        """Retorna rodapé do relatório TXT"""
        return f"""
{'='*80}
                                DISCLAIMER
{'='*80}

Este relatório foi gerado por uma ferramenta automatizada de escaneamento
de vulnerabilidades para fins educacionais e de teste de segurança.

IMPORTANTE:
• Use apenas em sistemas próprios ou com autorização explícita
• Este scanner realiza verificações básicas e pode não detectar todas as vulnerabilidades
• Recomenda-se análise manual adicional por profissionais de segurança
• O uso inadequado pode violar leis locais e federais

Relatório gerado em: {datetime.now().strftime('%d/%m/%Y às %H:%M:%S')}
{'='*80}
"""
    
    def _get_html_template(self):
        """Retorna template HTML completo"""
        return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Relatório de Vulnerabilidades - {self.results['target']}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
        }}
        .header p {{
            margin: 10px 0 0 0;
            opacity: 0.9;
        }}
        .content {{
            padding: 30px;
        }}
        .section {{
            margin-bottom: 30px;
            border-left: 4px solid #667eea;
            padding-left: 20px;
        }}
        .section h2 {{
            color: #333;
            border-bottom: 2px solid #eee;
            padding-bottom: 10px;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .summary-card {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #28a745;
        }}
        .summary-card.warning {{
            border-left-color: #ffc107;
        }}
        .summary-card.danger {{
            border-left-color: #dc3545;
        }}
        .port-list {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 15px;
        }}
        .port-item {{
            background: #e8f5e8;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #28a745;
        }}
        .vuln-item {{
            background: #fff5f5;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #dc3545;
            margin-bottom: 15px;
        }}
        .vuln-item.medium {{
            background: #fffbf0;
            border-left-color: #ffc107;
        }}
        .vuln-item.low {{
            background: #f8f9fa;
            border-left-color: #6c757d;
        }}
        .header-status {{
            display: inline-block;
            padding: 5px 10px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
        }}
        .header-present {{
            background: #d4edda;
            color: #155724;
        }}
        .header-missing {{
            background: #f8d7da;
            color: #721c24;
        }}
        .footer {{
            background: #333;
            color: white;
            padding: 20px;
            text-align: center;
            font-size: 0.9em;
        }}
        .timestamp {{
            color: #666;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Relatório de Vulnerabilidades</h1>
            <p>Alvo: <strong>{self.results['target']}</strong></p>
            <p class="timestamp">Gerado em: {datetime.now().strftime('%d/%m/%Y às %H:%M:%S')}</p>
        </div>
        
        <div class="content">
            {self._get_html_summary()}
            {self._get_html_port_results()}
            {self._get_html_http_results()}
        </div>
        
        <div class="footer">
            <p><strong>⚠️ DISCLAIMER:</strong> Este relatório foi gerado para fins educacionais e de teste de segurança.</p>
            <p>Use apenas em sistemas próprios ou com autorização explícita. Scanner de Vulnerabilidades v1.0</p>
        </div>
    </div>
</body>
</html>"""
    
    def _get_html_summary(self):
        """Retorna resumo em HTML"""
        html = '<div class="section"><h2>📊 Resumo Executivo</h2><div class="summary-grid">'
        
        if self.results.get('port_scan'):
            open_ports = len(self.results['port_scan']['open_ports'])
            total_ports = self.results['port_scan']['total_ports']
            card_class = "danger" if open_ports > 5 else "warning" if open_ports > 0 else ""
            
            html += f'''
            <div class="summary-card {card_class}">
                <h3>🔍 Scanner de Portas</h3>
                <p><strong>{open_ports}</strong> portas abertas de <strong>{total_ports}</strong> escaneadas</p>
                <p>Duração: {self.results['port_scan']['duration']:.2f}s</p>
            </div>'''
        
        if self.results.get('http_analysis'):
            vulns = len(self.results['http_analysis']['vulnerabilities'])
            card_class = "danger" if vulns > 3 else "warning" if vulns > 0 else ""
            
            html += f'''
            <div class="summary-card {card_class}">
                <h3>🌐 Análise HTTP</h3>
                <p><strong>{vulns}</strong> vulnerabilidades encontradas</p>
                <p>HTTP: {"✅" if self.results['http_analysis']['http_info'].get('accessible') else "❌"}</p>
                <p>HTTPS: {"✅" if self.results['http_analysis']['https_info'].get('accessible') else "❌"}</p>
            </div>'''
        
        html += '</div></div>'
        return html
    
    def _get_html_port_results(self):
        """Retorna resultados das portas em HTML"""
        if not self.results.get('port_scan'):
            return ""
        
        port_scan = self.results['port_scan']
        html = '<div class="section"><h2>🔍 Resultados do Scanner de Portas</h2>'
        
        if port_scan['open_ports']:
            html += '<div class="port-list">'
            for port_info in port_scan['open_ports']:
                html += f'''
                <div class="port-item">
                    <h4>Porta {port_info['port']} - {port_info['service']}</h4>
                    <p><strong>Status:</strong> Aberta</p>
                    {f"<p><strong>Banner:</strong> {port_info['banner'][:100]}...</p>" if port_info.get('banner') else ""}
                </div>'''
            html += '</div>'
        else:
            html += '<p>✅ Nenhuma porta aberta encontrada nos serviços testados.</p>'
        
        html += '</div>'
        return html
    
    def _get_html_http_results(self):
        """Retorna resultados HTTP em HTML"""
        if not self.results.get('http_analysis'):
            return ""
        
        http_analysis = self.results['http_analysis']
        html = '<div class="section"><h2>🌐 Análise HTTP/HTTPS</h2>'
        
        # Status dos serviços
        html += '<h3>Status dos Serviços</h3>'
        html += '<div class="summary-grid">'
        
        if http_analysis['http_info'].get('accessible'):
            html += f'''
            <div class="summary-card">
                <h4>HTTP (Porta 80)</h4>
                <p>Status: {http_analysis['http_info']['status_code']}</p>
                <p>Servidor: {http_analysis['http_info'].get('server', 'Desconhecido')}</p>
            </div>'''
        
        if http_analysis['https_info'].get('accessible'):
            html += f'''
            <div class="summary-card">
                <h4>HTTPS (Porta 443)</h4>
                <p>Status: {http_analysis['https_info']['status_code']}</p>
                <p>Servidor: {http_analysis['https_info'].get('server', 'Desconhecido')}</p>
            </div>'''
        
        html += '</div>'
        
        # Headers de segurança
        security_headers = http_analysis.get('security_headers', {})
        if security_headers:
            html += '<h3>Headers de Segurança</h3>'
            
            if security_headers.get('present'):
                html += '<h4>✅ Headers Presentes:</h4><p>'
                for header in security_headers['present']:
                    html += f'<span class="header-status header-present">{header["header"]}</span> '
                html += '</p>'
            
            if security_headers.get('missing'):
                html += '<h4>❌ Headers Ausentes:</h4><p>'
                for header in security_headers['missing']:
                    html += f'<span class="header-status header-missing">{header["header"]}</span> '
                html += '</p>'
        
        # Vulnerabilidades
        if http_analysis.get('vulnerabilities'):
            html += '<h3>🚨 Vulnerabilidades Identificadas</h3>'
            for vuln in http_analysis['vulnerabilities']:
                severity_class = vuln['severity'].lower()
                html += f'''
                <div class="vuln-item {severity_class}">
                    <h4>{vuln['type']} - Severidade: {vuln['severity']}</h4>
                    <p><strong>Descrição:</strong> {vuln['description']}</p>
                    <p><strong>Recomendação:</strong> {vuln['recommendation']}</p>
                </div>'''
        
        html += '</div>'
        return html
