"""
Interface de linha de comando (CLI) para o File Carving Recovery Tool.

Suporta dois modos:
  - Modo interativo (menu textual)
  - Modo batch via argparse (automacao/scripts)
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from typing import Optional

from .carver import scan_device
from .devices import DeviceInfo, get_device_size, list_drives
from .signatures import FILE_SIGNATURES, get_all_signature_names, get_signatures_by_names
from .utils import clear_screen, format_bytes, get_default_output_dir, is_admin, is_windows


# ---------------------------------------------------------------------------
# Header / banner
# ---------------------------------------------------------------------------

_BANNER = """
======================================================================
   FILE CARVING RECOVERY TOOL
   Recuperacao de arquivos por varredura de blocos brutos
======================================================================
"""


def _print_admin_warning() -> None:
    if not is_admin():
        print("  [!] ATENCAO: Este programa NAO esta rodando como Administrador.")
        print("      Acesso raw ao disco pode falhar sem permissoes elevadas.")
        print("      Recomendado: clique direito no terminal > 'Executar como Administrador'")
        print()


# ---------------------------------------------------------------------------
# Modo interativo (menus)
# ---------------------------------------------------------------------------

def _menu_listar_dispositivos() -> None:
    clear_screen()
    print(_BANNER)
    print("  Buscando dispositivos...\n")
    drives = list_drives()

    if not drives:
        print("  Nenhum dispositivo encontrado.")
    else:
        print(f"  {'#':<4} {'Dispositivo':<55} {'Path'}")
        print(f"  {'-'*4} {'-'*55} {'-'*30}")
        for i, d in enumerate(drives, 1):
            print(f"  {i:<4} {d.label:<55} {d.path}")
    print()
    input("  Pressione Enter para voltar ao menu principal.")


def _menu_selecionar_tipos() -> dict[str, dict]:
    """Retorna dict de assinaturas selecionadas pelo usuario."""
    clear_screen()
    print(_BANNER)
    print("  Selecione os tipos de arquivo para buscar:")
    print()
    sig_list = list(FILE_SIGNATURES.keys())
    for i, name in enumerate(sig_list, 1):
        sig = FILE_SIGNATURES[name]
        print(f"  [{i:>2}] {name:<12} (.{sig['extension']})  max: {format_bytes(sig['max_size'])}")
    print()
    print("  [0] Todos os tipos (recomendado)")
    print()
    choice = input("  Digite os numeros separados por virgula (ex: 1,3,5) ou 0 para todos: ").strip()

    if choice == "0" or choice == "":
        return FILE_SIGNATURES

    selected: dict[str, dict] = {}
    try:
        indices = [int(x.strip()) for x in choice.split(",")]
        for idx in indices:
            if 1 <= idx <= len(sig_list):
                name = sig_list[idx - 1]
                selected[name] = FILE_SIGNATURES[name]
    except ValueError:
        print("  Entrada invalida. Usando todos os tipos.")
        return FILE_SIGNATURES

    if not selected:
        print("  Nenhum tipo selecionado. Usando todos.")
        return FILE_SIGNATURES

    return selected


def _menu_configuracoes(config: dict) -> None:
    while True:
        clear_screen()
        print(_BANNER)
        print("  CONFIGURACOES")
        print()
        print(f"  [1] Pasta de saida padrao  : {config['output_dir']}")
        lim = config.get("limit_bytes")
        print(f"  [2] Limite de varredura    : {format_bytes(lim) if lim else 'Sem limite (disco inteiro)'}")
        print()
        print("  [0] Voltar")
        print()
        choice = input("  Escolha: ").strip()

        if choice == "1":
            novo = input(f"  Nova pasta de saida [{config['output_dir']}]: ").strip()
            if novo:
                config["output_dir"] = novo
                print(f"  Pasta atualizada para: {novo}")
                input("  Pressione Enter para continuar.")
        elif choice == "2":
            print("  Defina o limite de varredura em GB (0 = sem limite = disco inteiro).")
            val = input("  Limite em GB: ").strip()
            try:
                gb = float(val)
                config["limit_bytes"] = int(gb * 1024**3) if gb > 0 else None
                print(f"  Limite definido: {format_bytes(config['limit_bytes']) if config['limit_bytes'] else 'Sem limite'}")
                input("  Pressione Enter para continuar.")
            except ValueError:
                print("  Valor invalido.")
                input("  Pressione Enter para continuar.")
        elif choice == "0":
            break


def _menu_recuperacao(config: dict) -> None:
    clear_screen()
    print(_BANNER)

    print("  Buscando dispositivos...\n")
    drives = list_drives()

    if not drives:
        print("  Nenhum dispositivo encontrado. Verifique as permissoes.")
        input("  Pressione Enter para voltar.")
        return

    print(f"  {'#':<4} {'Dispositivo'}")
    print(f"  {'-'*4} {'-'*60}")
    for i, d in enumerate(drives, 1):
        print(f"  {i:<4} {d.label}")
    print()

    choice = input("  Selecione o dispositivo pelo numero (ou Enter para cancelar): ").strip()
    if not choice:
        return

    try:
        dev_idx = int(choice) - 1
        if dev_idx < 0 or dev_idx >= len(drives):
            raise ValueError
    except ValueError:
        print("  Selecao invalida.")
        input("  Pressione Enter para voltar.")
        return

    selected_drive = drives[dev_idx]
    device_path = selected_drive.path

    print(f"\n  Pasta de saida padrao: {config['output_dir']}")
    custom = input("  Pressione Enter para usar o padrao ou digite outro caminho: ").strip()
    output_dir = custom if custom else config["output_dir"]

    print()
    input("  Pressione Enter para selecionar os tipos de arquivo a recuperar...")
    selected_sigs = _menu_selecionar_tipos()

    clear_screen()
    print(_BANNER)
    print("  RESUMO DA OPERACAO:")
    print(f"    Dispositivo  : {device_path}")
    print(f"    Pasta saida  : {output_dir}")
    print(f"    Tipos        : {', '.join(selected_sigs.keys())}")
    lim = config.get("limit_bytes")
    print(f"    Limite       : {format_bytes(lim) if lim else 'Disco inteiro'}")
    print()

    try:
        from .carver import _HAS_TQDM

        if not _HAS_TQDM:
            print("  [!] tqdm nao instalado. Instale com: pip install tqdm")
            print("      A barra de progresso nao sera exibida.")
            print()
    except ImportError:
        pass

    confirm = input("  Confirmar inicio da varredura? [s/N]: ").strip().lower()
    if confirm != "s":
        print("  Cancelado.")
        input("  Pressione Enter para voltar.")
        return

    print()
    print("  Iniciando varredura... Pressione Ctrl+C para interromper a qualquer momento.")
    print()

    stop_flag = [False]
    start_time = time.time()

    try:
        found_counts = scan_device(
            device_path=device_path,
            output_dir=output_dir,
            selected_sigs=selected_sigs,
            limit_bytes=lim,
            stop_flag=stop_flag,
        )
    except KeyboardInterrupt:
        stop_flag[0] = True
        found_counts = {}

    elapsed = time.time() - start_time

    print()
    print("=" * 60)
    print("  VARREDURA CONCLUIDA")
    print("=" * 60)
    total_found = sum(found_counts.values())
    print(f"  Total de arquivos recuperados : {total_found}")
    print(f"  Tempo de execucao             : {elapsed:.1f} segundos")
    print(f"  Pasta de saida                : {output_dir}")
    print()
    if total_found > 0:
        print("  Arquivos por tipo:")
        for sig_name, count in sorted(found_counts.items(), key=lambda x: -x[1]):
            if count > 0:
                ext = FILE_SIGNATURES.get(sig_name, {}).get("extension", "?")
                folder = FILE_SIGNATURES.get(sig_name, {}).get("folder", sig_name)
                print(f"    {sig_name:<12} (.{ext}) : {count} arquivo(s)  ->  {output_dir}\\{folder}")
    print()
    print(f"  Log detalhado salvo em: {os.path.join(output_dir, 'recovery_log.txt')}")
    print()
    input("  Pressione Enter para voltar ao menu principal.")


def run_interactive() -> None:
    """Executa o modo interativo (menu textual)."""
    config: dict = {
        "output_dir": get_default_output_dir(),
        "limit_bytes": None,
    }

    clear_screen()
    print(_BANNER)

    try:
        from .carver import _HAS_TQDM

        if not _HAS_TQDM:
            print("  [!] Dependencia 'tqdm' nao encontrada.")
            print("      Para barra de progresso, instale com:")
            print("        pip install tqdm")
            print()
            print("  A ferramenta funcionara normalmente, sem a barra de progresso.")
            print()
            input("  Pressione Enter para continuar...")
    except ImportError:
        pass

    _print_admin_warning()
    if not is_admin():
        input("  Pressione Enter para continuar mesmo assim (alguns dispositivos podem falhar)...")

    try:
        _menu_principal_loop(config)
    except KeyboardInterrupt:
        print("\n\n  Encerrado pelo usuario.")
        sys.exit(0)


def _menu_principal_loop(config: dict) -> None:
    """Loop principal do menu interativo."""
    while True:
        clear_screen()
        print(_BANNER)
        _print_admin_warning()
        print(f"  Pasta de saida atual: {config['output_dir']}")
        lim = config.get("limit_bytes")
        print(f"  Limite de varredura:  {format_bytes(lim) if lim else 'Sem limite (disco inteiro)'}")
        print()
        print("  [1] Listar dispositivos disponiveis")
        print("  [2] Iniciar recuperacao de arquivos")
        print("  [3] Configuracoes")
        print("  [4] Sair")
        print()
        choice = input("  Escolha uma opcao: ").strip()

        if choice == "1":
            _menu_listar_dispositivos()
        elif choice == "2":
            _menu_recuperacao(config)
        elif choice == "3":
            _menu_configuracoes(config)
        elif choice == "4":
            print("\n  Encerrando. Ate logo!")
            sys.exit(0)
        else:
            print("  Opcao invalida. Pressione Enter para continuar.")
            input()


# ---------------------------------------------------------------------------
# Modo batch (argparse)
# ---------------------------------------------------------------------------

def _build_argparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="disk-recover",
        description="File Carving Recovery Tool — recupera arquivos de discos/pendrives formatados.",
        epilog="Exemplo: python -m file_carver --device \\\\.\\D: --output ./recuperados --types JPEG,PNG",
    )
    parser.add_argument(
        "-d", "--device",
        type=str,
        help="Caminho raw do dispositivo (ex: \\\\.\\D: ou /dev/sdb)",
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default=get_default_output_dir(),
        help=f"Pasta de saida para arquivos recuperados (padrao: {get_default_output_dir()})",
    )
    parser.add_argument(
        "-t", "--types",
        type=str,
        help="Tipos de arquivo para buscar, separados por virgula (ex: JPEG,PNG,PDF). Default: todos",
    )
    parser.add_argument(
        "-l", "--limit",
        type=str,
        help="Limite de varredura em bytes ou com unidade (ex: 1G, 500M, 100000000)",
    )
    parser.add_argument(
        "--list-devices",
        action="store_true",
        help="Lista dispositivos disponiveis e sai",
    )
    parser.add_argument(
        "--list-types",
        action="store_true",
        help="Lista tipos de arquivo suportados e sai",
    )
    return parser


def _parse_limit(limit_str: str) -> int:
    """Converte string de limite (ex: '1G', '500M') para bytes."""
    limit_str = limit_str.strip().upper()
    multipliers = {"K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
    if limit_str and limit_str[-1] in multipliers:
        return int(float(limit_str[:-1]) * multipliers[limit_str[-1]])
    return int(limit_str)


def run_batch(args: list[str] | None = None) -> None:
    """Executa o modo batch via argparse."""
    parser = _build_argparser()
    opts = parser.parse_args(args)

    # Comando: listar dispositivos
    if opts.list_devices:
        drives = list_drives()
        if not drives:
            print("Nenhum dispositivo encontrado.")
        else:
            print(f"{'#':<4} {'Dispositivo':<55} {'Path'}")
            print(f"{'-'*4} {'-'*55} {'-'*30}")
            for i, d in enumerate(drives, 1):
                print(f"{i:<4} {d.label:<55} {d.path}")
        return

    # Comando: listar tipos
    if opts.list_types:
        names = get_all_signature_names()
        print(f"{'#':<4} {'Tipo':<14} {'Extensao':<10} {'Max Tamanho'}")
        print(f"{'-'*4} {'-'*14} {'-'*10} {'-'*15}")
        for i, name in enumerate(names, 1):
            sig = FILE_SIGNATURES[name]
            print(f"{i:<4} {name:<14} .{sig['extension']:<9} {format_bytes(sig['max_size'])}")
        return

    # Comando: recuperacao
    if not opts.device:
        parser.error("--device e obrigatorio para recuperacao (use --list-devices para ver opcoes)")

    # Resolver tipos
    selected_sigs = None
    if opts.types:
        names = [n.strip().upper() for n in opts.types.split(",")]
        selected_sigs = get_signatures_by_names(names)
        if not selected_sigs:
            parser.error(f"Nenhum tipo valido encontrado: {opts.types}")

    # Resolver limite
    limit_bytes = None
    if opts.limit:
        limit_bytes = _parse_limit(opts.limit)

    # Executar
    print(_BANNER)
    print(f"  Dispositivo : {opts.device}")
    print(f"  Saida       : {opts.output}")
    print(f"  Tipos       : {', '.join(selected_sigs.keys()) if selected_sigs else 'Todos'}")
    print(f"  Limite      : {format_bytes(limit_bytes) if limit_bytes else 'Sem limite'}")
    print()

    found = scan_device(
        device_path=opts.device,
        output_dir=opts.output,
        selected_sigs=selected_sigs,
        limit_bytes=limit_bytes,
    )

    total = sum(found.values())
    print(f"\nConcluido: {total} arquivo(s) recuperado(s).")
