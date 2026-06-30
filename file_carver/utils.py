"""
Funcoes utilitarias gerais: formatacao, deteccao de SO, permissao admin, etc.
"""

from __future__ import annotations

import ctypes
import os
import platform
import sys
from typing import Optional


def is_windows() -> bool:
    """Verifica se o sistema operacional e Windows."""
    return platform.system() == "Windows"


def is_admin() -> bool:
    """Verifica se o processo esta rodando com privilegios de administrador/root."""
    if is_windows():
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0  # type: ignore[attr-defined]
        except Exception:
            return False
    else:
        return os.geteuid() == 0  # type: ignore[attr-defined]


def clear_screen() -> None:
    """Limpa o terminal (cross-platform)."""
    os.system("cls" if is_windows() else "clear")


def format_bytes(size: Optional[int]) -> str:
    """Formata bytes em formato legivel (KB, MB, GB, etc.)."""
    if size is None:
        return "desconhecido"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0  # type: ignore[assignment]
    return f"{size:.1f} PB"


def get_default_output_dir() -> str:
    """Retorna o diretorio padrao para arquivos recuperados."""
    if is_windows():
        return os.path.join(os.environ.get("SystemDrive", "C:"), "Recovered_Files")
    return os.path.expanduser("~/Recovered_Files")


def ensure_output_dir(path: str) -> str:
    """Garante que o diretorio de saida existe, criando-o se necessario."""
    os.makedirs(path, exist_ok=True)
    return path


def get_log_path(output_dir: str) -> str:
    """Retorna o caminho completo do arquivo de log de recuperacao."""
    return os.path.join(output_dir, "recovery_log.txt")


def write_log(log_lines: list[str], log_path: str) -> None:
    """Escreve as linhas do log no arquivo especificado."""
    try:
        with open(log_path, "w", encoding="utf-8") as lf:
            lf.write("\n".join(log_lines))
    except Exception:
        pass
