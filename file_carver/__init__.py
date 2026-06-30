"""
file_carver — File Carving Recovery Tool

Recupera arquivos de discos/pendrives formatados buscando por magic bytes
nos setores brutos. Suporta Windows e Linux.
"""

from .carver import scan_device
from .devices import get_device_size, list_drives
from .signatures import FILE_SIGNATURES

__version__ = "2.0.0"
__author__ = "Luiz Petry"
