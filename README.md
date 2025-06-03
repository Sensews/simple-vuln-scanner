# 🔒 Scanner de Vulnerabilidades Simples

[![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Educational-orange.svg)](README.md)

Uma ferramenta educacional de cybersecurity para análise básica de vulnerabilidades, incluindo scanner de portas, análise de headers HTTP e geração de relatórios detalhados.

> ⚠️ **Aviso**: Esta ferramenta é destinada exclusivamente para fins educacionais e testes autorizados. Use apenas em sistemas que você possui ou tem permissão explícita para testar.

## 🎯 Características

- **Scanner de Portas**: Escaneamento TCP rápido e eficiente
- **Análise HTTP/HTTPS**: Verificação de headers de segurança e configurações
- **Detecção de Vulnerabilidades**: Identificação de falhas básicas de segurança
- **Relatórios Múltiplos**: Geração em formatos TXT, HTML e JSON
- **Interface Amigável**: Logs coloridos e interface de linha de comando intuitiva
- **Modular**: Código bem estruturado e facilmente extensível

## 📁 Estrutura do Projeto

```
simple-vuln-scanner/
├── vuln_scanner.py          # Script principal
├── requirements.txt         # Dependências Python
├── config.ini              # Configurações do scanner
├── examples.py             # Exemplos de uso
├── LICENSE                 # Licença MIT
├── README.md               # Documentação
├── modules/                # Módulos do scanner
│   ├── __init__.py
│   ├── port_scanner.py     # Scanner de portas
│   ├── http_analyzer.py    # Analisador HTTP
│   ├── report_generator.py # Gerador de relatórios
│   └── utils.py           # Utilitários
├── reports/               # Relatórios gerados
└── docs/                 # Documentação adicional
    └── technical_documentation.md
```

## 🚀 Instalação e Uso

### Pré-requisitos

- Python 3.7 ou superior
- pip (gerenciador de pacotes Python)

### Instalação

1. Clone ou baixe o projeto:
```bash
git clone <url-do-repositorio>
cd simple-vuln-scanner
```

2. Instale as dependências:
```bash
pip install -r requirements.txt
```

### Exemplos de Uso

#### Escaneamento Básico
```bash
python vuln_scanner.py -t google.com
```

#### Escaneamento de Portas Específicas
```bash
python vuln_scanner.py -t 192.168.1.1 -p 80,443,22,21
```

#### Escaneamento Completo (Portas + HTTP)
```bash
python vuln_scanner.py -t example.com --full-scan
```

#### Apenas Análise HTTP
```bash
python vuln_scanner.py -t site.com --http-only
```

#### Especificar Formato do Relatório
```bash
python vuln_scanner.py -t example.com -f html
python vuln_scanner.py -t example.com -f json
```

#### Configurações Personalizadas
```bash
# Usar arquivo de configuração personalizado
python vuln_scanner.py -t example.com --config custom_config.ini

# Ajustar timeout
python vuln_scanner.py -t example.com --timeout 5

# Modo verboso
python vuln_scanner.py -t example.com -v
```

## 📝 Configuração

O arquivo `config.ini` permite personalizar o comportamento do scanner:

```ini
[scan_settings]
default_timeout = 3
max_threads = 100
common_ports = 21,22,23,25,53,80,110,135,139,143,443,993,995,1723,3306,3389,5432,5900,8080

[http_settings]
http_timeout = 10
verify_ssl = false

[report_settings]
reports_directory = reports
default_format = txt
include_timestamp = true
```

## 🔍 Funcionalidades Detalhadas

### Scanner de Portas
- Escaneamento TCP multi-threaded
- Detecção de serviços comuns
- Banner grabbing
- Identificação de vulnerabilidades conhecidas por porta

### Análise HTTP/HTTPS
- Verificação de headers de segurança
- Detecção de tecnologias web
- Análise de certificados SSL
- Identificação de configurações inseguras

### Geração de Relatórios
- **TXT**: Relatório textual simples
- **HTML**: Relatório visual com gráficos
- **JSON**: Dados estruturados para integração

### Detecções de Segurança
- Protocolos inseguros (Telnet, FTP sem TLS)
- Headers de segurança ausentes
- Versões de software expostas
- Certificados SSL inválidos ou expirados

## 📊 Exemplo de Saída

```
╔═══════════════════════════════════════════════════════╗
║            Scanner de Vulnerabilidades Simples        ║
║                    Versão 1.0                         ║
║               Ferramenta de Cybersecurity             ║
╚═══════════════════════════════════════════════════════╝

🎯 Alvo: example.com
📡 Escaneando portas: 80,443,22,21
⏱️  Timeout: 3 segundos

🔍 RESULTADOS DO SCANNER DE PORTAS
✅ Porta 80/tcp aberta (HTTP)
✅ Porta 443/tcp aberta (HTTPS)
❌ Porta 22/tcp fechada
❌ Porta 21/tcp fechada

🌐 ANÁLISE HTTP/HTTPS
📋 Headers de Segurança:
  ⚠️  X-Frame-Options: Ausente
  ✅ X-Content-Type-Options: nosniff
  ⚠️  Strict-Transport-Security: Ausente

📄 Relatório salvo em: reports/example_com_20250603_142530.html
```

## 🔧 Desenvolvimento

### Estrutura de Classes

```python
# Exemplo de uso programático
from modules import PortScanner, HTTPAnalyzer, ReportGenerator

# Scanner de portas
scanner = PortScanner("example.com", "80,443")
port_results = scanner.scan()

# Análise HTTP
analyzer = HTTPAnalyzer("example.com")
http_results = analyzer.analyze()

# Geração de relatório
report = ReportGenerator({
    'port_scan': port_results,
    'http_analysis': http_results
})
report.generate('html', 'my_scan')
```

### Contribuindo

1. Fork o projeto
2. Crie uma branch para sua feature (`git checkout -b feature/nova-feature`)
3. Commit suas mudanças (`git commit -am 'Adiciona nova feature'`)
4. Push para a branch (`git push origin feature/nova-feature`)
5. Abra um Pull Request

## ⚖️ Aspectos Legais

### Uso Responsável
- ✅ Teste apenas em sistemas próprios
- ✅ Obtenha permissão escrita antes de testar sistemas de terceiros
- ✅ Respeite termos de serviço e leis locais
- ❌ Não use para atividades maliciosas
- ❌ Não teste sistemas sem autorização

### Disclaimer
Esta ferramenta é fornecida apenas para fins educacionais e de pesquisa em segurança. Os usuários são totalmente responsáveis pelo uso adequado e legal desta ferramenta. Os desenvolvedores não se responsabilizam por uso indevido ou danos causados.

## 📚 Recursos Adicionais

- [Documentação Técnica](docs/technical_documentation.md)
- [Exemplos de Uso](examples.py)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

## 🤝 Suporte

- 🐛 **Bugs**: Abra uma issue no repositório
- 💡 **Sugestões**: Use discussions para ideias
- 📧 **Contato**: Através das issues do GitHub

## 📜 Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.

---

**⭐ Se este projeto foi útil para você, considere dar uma estrela!**
python vuln_scanner.py -t target.com --format html -o meu_relatorio
```

#### Modo Verbose
```bash
python vuln_scanner.py -t target.com -v
```

### Parâmetros Disponíveis

| Parâmetro | Descrição | Exemplo |
|-----------|-----------|---------|
| `-t, --target` | Alvo (IP ou domínio) - **OBRIGATÓRIO** | `-t google.com` |
| `-p, --ports` | Portas para escanear | `-p 80,443,22` |
| `--full-scan` | Escaneamento completo | `--full-scan` |
| `--http-only` | Apenas análise HTTP | `--http-only` |
| `--format` | Formato do relatório (txt/html/json) | `--format html` |
| `-o, --output` | Nome do arquivo de saída | `-o relatorio` |
| `-v, --verbose` | Modo detalhado | `-v` |

## 📊 Tipos de Verificação

### Scanner de Portas
- Escaneamento TCP de portas especificadas
- Identificação de serviços comuns
- Captura de banners quando possível
- Detecção de protocolos inseguros (Telnet, FTP, etc.)

### Análise HTTP/HTTPS
- Verificação de acessibilidade HTTP/HTTPS
- Análise de headers de segurança:
  - `Strict-Transport-Security` (HSTS)
  - `X-Content-Type-Options`
  - `X-Frame-Options`
  - `Content-Security-Policy`
  - `X-XSS-Protection`
  - `Referrer-Policy`
  - `Permissions-Policy`
- Identificação de tecnologias web
- Análise básica de certificados SSL
- Detecção de versões de servidor expostas

### Vulnerabilidades Detectadas
- Protocolos inseguros (HTTP, Telnet, FTP)
- Headers de segurança ausentes
- Informações de servidor expostas
- Problemas de certificado SSL/TLS
- Software potencialmente desatualizado

## 📄 Formatos de Relatório

### TXT (Texto)
- Relatório simples e legível
- Ideal para análise rápida
- Compatível com qualquer editor

### HTML (Web)
- Interface visual moderna
- Gráficos e cores para facilitar análise
- Ideal para apresentações

### JSON (Dados)
- Formato estruturado para automação
- Ideal para integração com outras ferramentas
- Dados completos preservados

## 🛡️ Considerações de Segurança

### ⚠️ IMPORTANTE - USO ÉTICO

Esta ferramenta foi desenvolvida exclusivamente para:
- **Fins educacionais** e aprendizado de cybersecurity
- **Testes autorizados** em sistemas próprios
- **Auditorias de segurança** com permissão explícita

### ❌ NÃO USE PARA:
- Atacar sistemas sem autorização
- Atividades ilegais ou maliciosas
- Violação de termos de serviço

### 📋 Responsabilidades
- O usuário é responsável pelo uso adequado da ferramenta
- Sempre obtenha autorização antes de escanear sistemas terceiros
- Respeite leis locais e federais de cybersecurity
- Use apenas para fins legítimos e éticos

## 🔧 Desenvolvimento

### Estrutura dos Módulos

#### `port_scanner.py`
- Classe `PortScanner`
- Escaneamento multithread
- Captura de banners
- Identificação de serviços

#### `http_analyzer.py`
- Classe `HTTPAnalyzer`
- Análise HTTP/HTTPS
- Verificação de headers
- Análise SSL

#### `report_generator.py`
- Classe `ReportGenerator`
- Geração de relatórios múltiplos formatos
- Templates HTML responsivos

#### `utils.py`
- Funções auxiliares
- Sistema de logging
- Validação de alvos
- Utilitários gerais

### Extensibilidade

O projeto foi desenvolvido com foco na modularidade. Para adicionar novas funcionalidades:

1. Crie um novo módulo em `modules/`
2. Implemente a classe seguindo o padrão existente
3. Adicione a importação em `vuln_scanner.py`
4. Integre com o sistema de relatórios

## 🐛 Solução de Problemas

### Erro: "ModuleNotFoundError"
```bash
pip install -r requirements.txt
```

### Erro: "Permission denied"
- Execute como administrador (Windows) ou use `sudo` (Linux/macOS)
- Verifique firewall e antivírus

### Timeout em escaneamentos
- Aumente o timeout no código
- Verifique conectividade de rede
- Use `-v` para modo verbose

### Problemas com SSL
- Alguns sites podem ter configurações SSL restritivas
- O scanner desabilita verificação SSL para testes

## 📚 Recursos de Aprendizado

### Conceitos Abordados
- **Network Scanning**: Técnicas de descoberta de serviços
- **HTTP Security Headers**: Importância e implementação
- **SSL/TLS**: Configurações e análise de certificados
- **Vulnerability Assessment**: Metodologias básicas
- **Report Generation**: Documentação de achados

### Para Aprofundar
- OWASP Top 10
- NIST Cybersecurity Framework
- Metodologias de Penetration Testing
- Tools como Nmap, Burp Suite, OWASP ZAP

## 🤝 Contribuição

Contribuições são bem-vindas! Para contribuir:

1. Fork o projeto
2. Crie uma branch para sua feature
3. Commit suas mudanças
4. Push para a branch
5. Abra um Pull Request

## 📝 Licença

Este projeto está sob a licença MIT. Veja o arquivo [LICENSE](LICENSE) para detalhes.

## 👨‍💻 Autor

Desenvolvido como projeto educacional de cybersecurity.

---

**⚡ Dica**: Use este projeto como base para aprender conceitos de segurança, mas sempre pratique ethical hacking responsável!

**🎓 Portfólio**: Esta ferramenta demonstra conhecimentos em:
- Python programming
- Network security
- Web security
- Vulnerability assessment
- Report generation
- Security best practices
