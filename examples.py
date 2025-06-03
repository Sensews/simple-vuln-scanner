#!/usr/bin/env python3
"""
Exemplo de Uso do Scanner de Vulnerabilidades
============================================

Este script demonstra como usar os módulos do scanner
de vulnerabilidades de forma programática.
"""

from modules import PortScanner, HTTPAnalyzer, ReportGenerator, logger

def exemplo_scanner_basico():
    """Exemplo básico de uso do scanner"""
    
    # Configurar alvo
    target = "httpbin.org"  # Site de teste público
    ports = "80,443"
    
    print("="*60)
    print("           EXEMPLO DE USO - SCANNER BÁSICO")
    print("="*60)
    print(f"Alvo: {target}")
    print(f"Portas: {ports}")
    print("="*60)
    
    # 1. Scanner de Portas
    print("\n1. Executando Scanner de Portas...")
    port_scanner = PortScanner(target, ports)
    port_results = port_scanner.scan()
    
    # Exibir resultados das portas
    if port_results['open_ports']:
        print(f"✅ Encontradas {len(port_results['open_ports'])} portas abertas:")
        for port in port_results['open_ports']:
            print(f"   - Porta {port['port']}: {port['service']}")
    else:
        print("❌ Nenhuma porta aberta encontrada")
    
    # 2. Análise HTTP
    print("\n2. Executando Análise HTTP...")
    http_analyzer = HTTPAnalyzer(target)
    http_results = http_analyzer.analyze()
    
    # Exibir resultados HTTP
    if http_results['http_info'].get('accessible'):
        print(f"✅ HTTP acessível (Status: {http_results['http_info']['status_code']})")
    
    if http_results['https_info'].get('accessible'):
        print(f"✅ HTTPS acessível (Status: {http_results['https_info']['status_code']})")
    
    # Headers de segurança
    security_headers = http_results.get('security_headers', {})
    if security_headers:
        print(f"🔒 Headers de segurança presentes: {len(security_headers.get('present', []))}")
        print(f"⚠️  Headers de segurança ausentes: {len(security_headers.get('missing', []))}")
    
    # Vulnerabilidades
    vulnerabilities = http_results.get('vulnerabilities', [])
    if vulnerabilities:
        print(f"🚨 Vulnerabilidades encontradas: {len(vulnerabilities)}")
        for vuln in vulnerabilities:
            print(f"   - {vuln['type']} (Severidade: {vuln['severity']})")
    
    # 3. Gerar Relatório
    print("\n3. Gerando Relatório...")
    
    # Combinar resultados
    scan_results = {
        'target': target,
        'timestamp': port_results['start_time'],
        'port_scan': port_results,
        'http_analysis': http_results
    }
    
    # Gerar relatório HTML
    report_gen = ReportGenerator(scan_results)
    report_file = report_gen.generate('html', f'exemplo_{target}')
    
    print(f"📄 Relatório gerado: {report_file}")
    print("\n✅ Exemplo concluído com sucesso!")
    
    return scan_results


def exemplo_scanner_personalizado():
    """Exemplo de scanner com configurações personalizadas"""
    
    print("\n" + "="*60)
    print("        EXEMPLO DE USO - SCANNER PERSONALIZADO")
    print("="*60)
    
    # Configurações personalizadas
    target = "example.com"
    custom_ports = "21,22,23,25,53,80,135,139,443,3389"
    
    print(f"Alvo: {target}")
    print(f"Portas customizadas: {custom_ports}")
    
    try:
        # Scanner com timeout personalizado
        print("\n🔍 Iniciando escaneamento personalizado...")
        port_scanner = PortScanner(target, custom_ports, timeout=2, max_threads=50)
        results = port_scanner.scan()
        
        print(f"⏱️  Escaneamento concluído em {results['duration']:.2f} segundos")
        print(f"📊 Resultados: {results['summary']['open_count']} portas abertas de {results['summary']['total_scanned']} escaneadas")
        
        # Listar portas abertas com detalhes
        if results['open_ports']:
            print("\n🔓 Portas Abertas Detalhadas:")
            for port in results['open_ports']:
                print(f"   └─ Porta {port['port']} ({port['service']})")
                if port.get('banner'):
                    print(f"      Banner: {port['banner'][:80]}...")
        
        return results
        
    except Exception as e:
        logger.error(f"Erro no escaneamento personalizado: {e}")
        return None


def main():
    """Função principal dos exemplos"""
    
    print("🔒 SCANNER DE VULNERABILIDADES - EXEMPLOS DE USO")
    print("=" * 60)
    print("⚠️  AVISO: Use apenas em sistemas próprios ou com autorização!")
    print("=" * 60)
    
    # Definir modo verbose
    logger.set_verbose(True)
    
    try:
        # Exemplo 1: Scanner básico
        results1 = exemplo_scanner_basico()
        
        # Exemplo 2: Scanner personalizado
        results2 = exemplo_scanner_personalizado()
        
        print("\n" + "="*60)
        print("              EXEMPLOS CONCLUÍDOS")
        print("="*60)
        print("📚 Verifique os relatórios gerados na pasta 'reports/'")
        print("📖 Consulte o README.md para mais exemplos de uso")
        print("🛡️  Lembre-se: use de forma ética e responsável!")
        
    except KeyboardInterrupt:
        print("\n❌ Execução interrompida pelo usuário")
    except Exception as e:
        logger.error(f"Erro durante execução dos exemplos: {e}")


if __name__ == "__main__":
    main()
