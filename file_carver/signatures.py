"""
Base de dados de assinaturas de arquivos (magic bytes) para file carving.

Cada assinatura define: header, offset, extensao, tamanho maximo, footer
(opcional) e metadados para verificacao secundaria.
"""

from __future__ import annotations

from typing import Optional


# Cada entrada: (header_bytes, header_offset, extensao, tamanho_max, footer_bytes ou None)
# tamanho_max em bytes. footer_bytes: buscar este padrao para saber onde o arquivo termina.

FILE_SIGNATURES: dict[str, dict] = {
    "JPEG": {
        "header": bytes([0xFF, 0xD8, 0xFF]),
        "offset": 0,
        "extension": "jpg",
        "max_size": 15 * 1024 * 1024,  # 15 MB
        "footer": bytes([0xFF, 0xD9]),
        "folder": "JPEG",
    },
    "PNG": {
        "header": bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
        "offset": 0,
        "extension": "png",
        "max_size": 20 * 1024 * 1024,
        "footer": bytes([0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]),  # IEND chunk CRC
        "folder": "PNG",
    },
    "PDF": {
        "header": b"%PDF",
        "offset": 0,
        "extension": "pdf",
        "max_size": 50 * 1024 * 1024,
        "footer": b"%%EOF",
        "folder": "PDF",
    },
    "GIF87": {
        "header": b"GIF87a",
        "offset": 0,
        "extension": "gif",
        "max_size": 10 * 1024 * 1024,
        "footer": bytes([0x00, 0x3B]),
        "folder": "GIF",
    },
    "GIF89": {
        "header": b"GIF89a",
        "offset": 0,
        "extension": "gif",
        "max_size": 10 * 1024 * 1024,
        "footer": bytes([0x00, 0x3B]),
        "folder": "GIF",
    },
    "BMP": {
        "header": bytes([0x42, 0x4D]),
        "offset": 0,
        "extension": "bmp",
        "max_size": 30 * 1024 * 1024,
        "footer": None,  # usa tamanho do header
        "folder": "BMP",
        "size_offset": 2,  # campo de tamanho no header BMP (little-endian uint32 em offset 2)
        "size_length": 4,
    },
    "ZIP": {
        "header": bytes([0x50, 0x4B, 0x03, 0x04]),
        "offset": 0,
        "extension": "zip",
        "max_size": 200 * 1024 * 1024,
        "footer": bytes([0x50, 0x4B, 0x05, 0x06]),  # end of central directory
        "folder": "ZIP",
    },
    "DOCX": {
        # DOCX/XLSX/PPTX sao ZIPs com conteudo especifico; detectados pelo mesmo magic
        # Diferenciados pelo nome interno (word/, xl/, ppt/)
        "header": bytes([0x50, 0x4B, 0x03, 0x04]),
        "offset": 0,
        "extension": "docx",
        "max_size": 100 * 1024 * 1024,
        "footer": bytes([0x50, 0x4B, 0x05, 0x06]),
        "folder": "DOCX_XLSX",
        "skip": True,  # Sera tratado via ZIP, evitar duplicata
    },
    "MP3_ID3": {
        "header": b"ID3",
        "offset": 0,
        "extension": "mp3",
        "max_size": 20 * 1024 * 1024,
        "footer": None,
        "folder": "MP3",
    },
    "MP3_SYNC": {
        "header": bytes([0xFF, 0xFB]),
        "offset": 0,
        "extension": "mp3",
        "max_size": 20 * 1024 * 1024,
        "footer": None,
        "folder": "MP3",
    },
    "MP4": {
        # ftyp box aparece em offset 4 da assinatura do container ISO
        "header": b"ftyp",
        "offset": 4,
        "extension": "mp4",
        "max_size": 2 * 1024 * 1024 * 1024,  # 2 GB
        "footer": None,
        "folder": "MP4",
        # MP4 requer verificacao adicional: o box anterior ao ftyp deve ter
        # tamanho valido (4..100 bytes) e os 4 bytes antes do ftyp devem ser
        # impressiveis ASCII (brand do ISO base media file format).
        "validate": "mp4",
    },
    "AVI": {
        "header": b"RIFF",
        "offset": 0,
        "extension": "avi",
        "max_size": 2 * 1024 * 1024 * 1024,
        "footer": None,
        "folder": "AVI",
        "secondary_check_offset": 8,
        "secondary_check": b"AVI ",
    },
    "WAV": {
        "header": b"RIFF",
        "offset": 0,
        "extension": "wav",
        "max_size": 300 * 1024 * 1024,
        "footer": None,
        "folder": "WAV",
        "secondary_check_offset": 8,
        "secondary_check": b"WAVE",
    },
    "EXE_MZ": {
        "header": bytes([0x4D, 0x5A]),
        "offset": 0,
        "extension": "exe",
        "max_size": 100 * 1024 * 1024,
        "footer": None,
        "folder": "EXE",
    },
    "TIFF_LE": {
        "header": bytes([0x49, 0x49, 0x2A, 0x00]),
        "offset": 0,
        "extension": "tif",
        "max_size": 100 * 1024 * 1024,
        "footer": None,
        "folder": "TIFF",
    },
    "TIFF_BE": {
        "header": bytes([0x4D, 0x4D, 0x00, 0x2A]),
        "offset": 0,
        "extension": "tif",
        "max_size": 100 * 1024 * 1024,
        "footer": None,
        "folder": "TIFF",
    },
    "PSD": {
        "header": bytes([0x38, 0x42, 0x50, 0x53]),
        "offset": 0,
        "extension": "psd",
        "max_size": 500 * 1024 * 1024,
        "footer": None,
        "folder": "PSD",
    },
    "RAR4": {
        "header": bytes([0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00]),
        "offset": 0,
        "extension": "rar",
        "max_size": 500 * 1024 * 1024,
        "footer": bytes([0xC4, 0x3D, 0x7B, 0x00, 0x40, 0x07, 0x00]),
        "folder": "RAR",
    },
    "RAR5": {
        "header": bytes([0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00]),
        "offset": 0,
        "extension": "rar",
        "max_size": 500 * 1024 * 1024,
        "footer": None,
        "folder": "RAR",
    },
    "SQLite": {
        "header": b"SQLite format 3\x00",
        "offset": 0,
        "extension": "db",
        "max_size": 500 * 1024 * 1024,
        "footer": None,
        "folder": "SQLite",
    },
    "XML": {
        "header": b"<?xml",
        "offset": 0,
        "extension": "xml",
        "max_size": 50 * 1024 * 1024,
        "footer": None,
        "folder": "XML",
    },
    "OGG": {
        "header": b"OggS",
        "offset": 0,
        "extension": "ogg",
        "max_size": 100 * 1024 * 1024,
        "footer": None,
        "folder": "OGG",
    },
    "FLAC": {
        "header": b"fLaC",
        "offset": 0,
        "extension": "flac",
        "max_size": 300 * 1024 * 1024,
        "footer": None,
        "folder": "FLAC",
    },
}

# Remover entradas marcadas como skip (DOCX duplica ZIP)
FILE_SIGNATURES = {k: v for k, v in FILE_SIGNATURES.items() if not v.get("skip", False)}


def get_signatures_by_names(names: list[str]) -> dict[str, dict]:
    """Retorna subconjunto de assinaturas pelos nomes informados."""
    return {k: v for k, v in FILE_SIGNATURES.items() if k in names}


def get_all_signature_names() -> list[str]:
    """Retorna lista ordenada com todos os nomes de assinaturas disponiveis."""
    return sorted(FILE_SIGNATURES.keys())
