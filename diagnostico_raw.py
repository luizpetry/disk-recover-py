"""Diagnostico: verifica se o conteudo dos arquivos visiveis no volume
aparece na leitura raw do dispositivo.

Por que isso importa: o file carving le os setores brutos do volume
(\\\\.\\E:). Se o conteudo que o Windows mostra em E:\\ nao aparecer nessa
leitura, NENHUMA ferramenta de carving vai recuperar nada — o problema
esta no dispositivo/cache, nao no carver.

Uso (em um terminal como Administrador, com os arquivos de teste AINDA
gravados no pendrive):

    python diagnostico_raw.py E
"""

from __future__ import annotations

import os
import re
import sys

CHUNK = 8 * 1024 * 1024  # 8 MB por leitura
NEEDLE_LEN = 64

# Assinaturas procuradas no modo pos-formatacao (sem arquivos visiveis)
SIGNATURES = {
    "PNG": bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
    "JPEG": bytes([0xFF, 0xD8, 0xFF, 0xE0]),
    "JPEG_EXIF": bytes([0xFF, 0xD8, 0xFF, 0xE1]),
    "ZIP": bytes([0x50, 0x4B, 0x03, 0x04]),
    "PDF": b"%PDF",
}


def _pick_needle(path: str) -> bytes:
    """Escolhe 64 bytes distintivos do arquivo (evita trechos constantes)."""
    with open(path, "rb") as fh:
        head = fh.read(64 * 1024)
    for offset in range(0, max(1, len(head) - NEEDLE_LEN), 1024):
        needle = head[offset : offset + NEEDLE_LEN]
        if len(needle) == NEEDLE_LEN and len(set(needle)) >= 16:
            return needle
    return head[:NEEDLE_LEN]


def _scan_signatures(raw: str) -> None:
    """Varre o volume raw procurando assinaturas de arquivos conhecidas."""
    try:
        dev = open(raw, "rb", buffering=0)
    except PermissionError:
        print("[ERRO] Acesso negado — execute o terminal como Administrador.")
        return
    except Exception as e:
        print(f"[ERRO] Nao foi possivel abrir {raw}: {e}")
        return

    max_needle = max(len(s) for s in SIGNATURES.values())
    hits: dict[str, list[int]] = {name: [] for name in SIGNATURES}
    pos = 0
    tail = b""
    gb_reported = 0
    try:
        while True:
            try:
                block = dev.read(CHUNK)
            except Exception as e:
                print(f"[AVISO] Leitura falhou no offset {pos:,}: {e}")
                break
            if not block:
                break
            combined = tail + block
            base = pos - len(tail)
            for name, sig in SIGNATURES.items():
                if len(hits[name]) >= 50:
                    continue
                for m in re.finditer(re.escape(sig), combined):
                    off = base + m.start()
                    if not hits[name] or off > hits[name][-1]:
                        hits[name].append(off)
                        if len(hits[name]) >= 50:
                            break
            tail = combined[-(max_needle - 1):]
            pos += len(block)
            gb = pos // (1024 ** 3)
            if gb > gb_reported:
                gb_reported = gb
                print(f"  ... {gb} GB varridos")
    finally:
        dev.close()

    print()
    total = sum(len(v) for v in hits.values())
    for name, offsets in hits.items():
        if offsets:
            shown = ", ".join(f"{o:,}" for o in offsets[:5])
            extra = " ..." if len(offsets) >= 50 else ""
            print(f"  {name:<10}: {len(offsets)} ocorrencia(s) — offsets: {shown}{extra}")
    if total:
        print()
        print("[OK] Ha assinaturas de arquivos nos setores brutos — os dados")
        print("sobreviveram a formatacao. Rode a recuperacao normalmente:")
        print("  python -m file_carver --device \\\\.\\E: --output ./recuperados")
    else:
        print("[!!] NENHUMA assinatura encontrada no volume inteiro.")
        print("A formatacao zerou (ou o dispositivo descartou) os dados.")
        print("Causas: formatacao completa em vez de rapida; TRIM/discard do")
        print("dispositivo; ou o volume foi recriado com outro offset.")


def main() -> None:
    letter = (sys.argv[1] if len(sys.argv) > 1 else "E").strip(":\\").upper()
    root = f"{letter}:\\"
    raw = f"\\\\.\\{letter}:"

    if not os.path.isdir(root):
        print(f"[ERRO] Unidade {root} nao encontrada.")
        return

    # 1. Lista arquivos visiveis no sistema de arquivos
    candidates: list[tuple[str, int]] = []
    for dirpath, dirs, files in os.walk(root):
        # ignora pastas de sistema
        dirs[:] = [d for d in dirs if not d.startswith("$") and d != "System Volume Information"]
        for name in files:
            p = os.path.join(dirpath, name)
            try:
                size = os.path.getsize(p)
            except OSError:
                continue
            if size >= 4096:
                candidates.append((p, size))
        if len(candidates) >= 20:
            break

    if not candidates:
        print(f"Nenhum arquivo >= 4 KB visivel em {root} (volume vazio/formatado).")
        print("Varrendo o volume bruto em busca de assinaturas de arquivos")
        print("(PNG, JPEG, ZIP, PDF) para saber se os dados sobreviveram...\n")
        _scan_signatures(raw)
        return

    print(f"Arquivos visiveis em {root} (ate 20):")
    for p, s in candidates[:20]:
        print(f"  {s:>12,} bytes  {p}")

    target, size = candidates[0]
    needle = _pick_needle(target)
    print(f"\nArquivo de referencia: {target} ({size:,} bytes)")
    print(f"Procurando um trecho de {NEEDLE_LEN} bytes dele na leitura raw de {raw} ...")
    print("(isso le o volume inteiro; aguarde)\n")

    # 2. Varre o volume raw procurando o trecho
    try:
        dev = open(raw, "rb", buffering=0)
    except PermissionError:
        print("[ERRO] Acesso negado — execute o terminal como Administrador.")
        return
    except Exception as e:
        print(f"[ERRO] Nao foi possivel abrir {raw}: {e}")
        return

    pos = 0
    tail = b""
    found = -1
    gb_reported = 0
    try:
        while True:
            try:
                block = dev.read(CHUNK)
            except Exception as e:
                print(f"[AVISO] Leitura falhou no offset {pos:,}: {e}")
                break
            if not block:
                break
            combined = tail + block
            idx = combined.find(needle)
            if idx != -1:
                found = pos - len(tail) + idx
                break
            tail = combined[-(NEEDLE_LEN - 1):]
            pos += len(block)
            gb = pos // (1024 ** 3)
            if gb > gb_reported:
                gb_reported = gb
                print(f"  ... {gb} GB varridos")
    finally:
        dev.close()

    print()
    if found >= 0:
        print(f"[OK] Conteudo ENCONTRADO no offset raw {found:,}.")
        print("A leitura raw enxerga os dados do volume — o file carving deve")
        print("funcionar. Se a recuperacao ainda falhar, o problema e outro.")
    else:
        print("[!!] Conteudo NAO encontrado na leitura raw do volume inteiro.")
        print()
        print("Ou seja: o que o Windows mostra como arquivo NAO esta visivel nos")
        print("setores brutos. Nenhum carving funciona nessa condicao. Causas:")
        print("  1. Cache de escrita — use 'Remover hardware com seguranca',")
        print("     reconecte o pendrive e rode este diagnostico de novo;")
        print("  2. Pendrive FALSIFICADO (capacidade adulterada) ou controlador")
        print("     defeituoso — teste com a ferramenta H2testw/ValiDrive;")
        print("  3. Volume criptografado ou virtual (BitLocker To Go, etc.).")


if __name__ == "__main__":
    main()
