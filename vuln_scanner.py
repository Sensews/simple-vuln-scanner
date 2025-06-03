#!/usr/bin/env python3
"""
Scanner de Vulnerabilidades Simples
====================================

Ferramenta de cybersecurity para análise básica de vulnerabilidades
incluindo scanner de portas, análise de headers HTTP e geração de relatórios.

Autor: [Seu Nome]
Data: Junho 2025
Versão: 1.0
"""

import argparse
import sys
import os
from datetime import datetime

# Importando módulos personalizados
from modules.port_scanner import PortScanner
from modules.http_analyzer import HTTPAnalyzer
from modules.report_generator import ReportGenerator
from modules.utils import logger, validate_target


def print_banner():
    """Exibe o banner do aplicativo"""
    banner = """
    ╔═══════════════════════════════════════════════════════╗
    ║            Scanner de Vulnerabilidades Simples        ║
    ║                    Versão 1.0                         ║
    ║               Ferramenta de Cybersecurity             ║
    ╚═══════════════════════════════════════════════════════╝
    """
    print(banner)


def main():
    """Função principal do scanner"""
    print_banner()
    
    # Configuração dos argumentos da linha de comando
    parser = argparse.ArgumentParser(
        description="Scanner de Vulnerabilidades Simples",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  python vuln_scanner.py -t google.com
  python vuln_scanner.py -t 192.168.1.1 -p 80,443,22
  python vuln_scanner.py -t example.com --full-scan
        """
    )
    
    parser.add_argument(
        '-t', '--target',
        required=True,
        help='Alvo para escaneamento (IP ou domínio)'
    )
    
    parser.add_argument(
        '-p', '--ports',
        default='21,22,23,25,53,80,110,135,139,143,443,993,995,1723,3306,3389,5432,5900,8080',
        help='Portas para escanear (separadas por vírgula). Padrão: portas mais comuns'
    )
    
    parser.add_argument(
        '--full-scan',
        action='store_true',
        help='Executa escaneamento completo (portas + análise HTTP)'
    )
    
    parser.add_argument(
        '--http-only',
        action='store_true',
        help='Executa apenas análise HTTP'
    )
    
    parser.add_argument(
        '--format',
        choices=['txt', 'html', 'json'],
        default='txt',
        help='Formato do relatório (padrão: txt)'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Nome do arquivo de saída (sem extensão)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Modo verbose (mais detalhes)'
    )
    
    args = parser.parse_args()
    
    # Configurar logger
    logger.set_verbose(args.verbose)
    
    # Validar alvo
    if not validate_target(args.target):
        logger.error(f"Alvo inválido: {args.target}")
        sys.exit(1)
    
    logger.info(f"Iniciando escaneamento do alvo: {args.target}")
    
    # Inicializar resultados
    scan_results = {
        'target': args.target,
        'timestamp': datetime.now().isoformat(),
        'port_scan': None,
        'http_analysis': None
    }
    
    try:
        # Scanner de Portas
        if not args.http_only:
            logger.info("Iniciando scanner de portas...")
            port_scanner = PortScanner(args.target, args.ports)
            scan_results['port_scan'] = port_scanner.scan()
            
            if scan_results['port_scan']['open_ports']:
                logger.success(f"Encontradas {len(scan_results['port_scan']['open_ports'])} portas abertas")
            else:
                logger.warning("Nenhuma porta aberta encontrada")
        
        # Análise HTTP
        if args.full_scan or args.http_only:
            logger.info("Iniciando análise HTTP...")
            http_analyzer = HTTPAnalyzer(args.target)
            scan_results['http_analysis'] = http_analyzer.analyze()
            
            if scan_results['http_analysis']['vulnerabilities']:
                logger.warning(f"Encontradas {len(scan_results['http_analysis']['vulnerabilities'])} possíveis vulnerabilidades HTTP")
        
        # Gerar relatório
        logger.info("Gerando relatório...")
        report_gen = ReportGenerator(scan_results)
        
        # Definir nome do arquivo se não fornecido
        if not args.output:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            args.output = f"scan_{args.target}_{timestamp}"
        
        report_file = report_gen.generate(args.format, args.output)
        logger.success(f"Relatório salvo em: {report_file}")
        
        # Exibir resumo
        print_summary(scan_results)
        
    except KeyboardInterrupt:
        logger.warning("\nEscaneamento interrompido pelo usuário")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Erro durante o escaneamento: {str(e)}")
        sys.exit(1)


def print_summary(results):
    """Exibe um resumo dos resultados"""
    print("\n" + "="*50)
    print("             RESUMO DO ESCANEAMENTO")
    print("="*50)
    
    if results['port_scan']:
        open_ports = len(results['port_scan']['open_ports'])
        print(f"Portas abertas encontradas: {open_ports}")
        
        if open_ports > 0:
            print("Portas abertas:")
            for port_info in results['port_scan']['open_ports']:
                service = port_info.get('service', 'Desconhecido')
                print(f"  - Porta {port_info['port']}: {service}")
    
    if results['http_analysis']:
        vulns = len(results['http_analysis']['vulnerabilities'])
        print(f"Possíveis vulnerabilidades HTTP: {vulns}")
        
        if vulns > 0:
            print("Vulnerabilidades encontradas:")
            for vuln in results['http_analysis']['vulnerabilities']:
                print(f"  - {vuln['type']}: {vuln['description']}")
    
    print("="*50)


if __name__ == "__main__":
    main()
