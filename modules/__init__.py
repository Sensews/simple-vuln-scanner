"""
Módulos do Scanner de Vulnerabilidades
=====================================

Este pacote contém todos os módulos necessários para o funcionamento
do scanner de vulnerabilidades simples.

Módulos disponíveis:
- port_scanner: Scanner de portas TCP
- http_analyzer: Analisador de serviços HTTP/HTTPS
- report_generator: Gerador de relatórios
- utils: Utilitários e funções auxiliares
"""

__version__ = "1.0.0"
__author__ = "Scanner de Vulnerabilidades"

# Importar classes principais para facilitar o uso
from .port_scanner import PortScanner
from .http_analyzer import HTTPAnalyzer
from .report_generator import ReportGenerator
from .utils import logger, validate_target

__all__ = [
    'PortScanner',
    'HTTPAnalyzer', 
    'ReportGenerator',
    'logger',
    'validate_target'
]
