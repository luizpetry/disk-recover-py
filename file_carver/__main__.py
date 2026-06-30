"""
Ponto de entrada do file_carver.

Uso interativo:    python -m file_carver
Uso batch:         python -m file_carver --device \\\\.\\D: --output ./out
Listar dispositivos: python -m file_carver --list-devices
"""

from __future__ import annotations

import sys


def main() -> None:
    # Se houver argumentos de linha de comando, usar modo batch
    if len(sys.argv) > 1:
        from .cli import run_batch

        run_batch()
    else:
        from .cli import run_interactive

        run_interactive()


if __name__ == "__main__":
    main()
