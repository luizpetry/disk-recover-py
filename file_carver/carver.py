"""
Engine de file carving — varre dispositivos de bloco buscando assinaturas
de arquivos (magic bytes) e extraindo os arquivos encontrados.

Correcoes em relacao ao recover.py original:
  - Bug fix: scan_size=None nao causa mais TypeError no tqdm/comparacao
  - Bug fix: duplicacao por overlap buffer eliminada com rastreamento global
  - Melhoria: validacao MP4 reduz falsos positivos
  - Melhoria: deduplicacao via hash MD5
  - Melhoria: validacao basica de integridade de arquivos extraidos
"""

from __future__ import annotations

import datetime
import hashlib
import os
import struct
from typing import Callable, Optional

from .signatures import FILE_SIGNATURES
from .utils import format_bytes, get_log_path, write_log

# Verificacao de tqdm
try:
    from tqdm import tqdm  # noqa: F401

    _HAS_TQDM = True
except ImportError:
    _HAS_TQDM = False

# Constantes do engine
CHUNK_SIZE: int = 1 * 1024 * 1024  # 1 MB por leitura
SECTOR_SIZE: int = 512
MAX_HEADER_LEN: int = 32  # maior magic bytes que usamos
OVERLAP_SIZE: int = 65536  # 64 KB de sobreposicao entre chunks


def _find_footer(data: bytes, footer_bytes: bytes, start_pos: int = 0) -> int:
    """Busca footer_bytes em data a partir de start_pos.

    Retorna posicao do fim do footer ou -1 se nao encontrado.
    """
    idx = data.find(footer_bytes, start_pos)
    if idx == -1:
        return -1
    return idx + len(footer_bytes)


def _validate_mp4(chunk: bytes, hit_pos: int) -> bool:
    """Validacao adicional para MP4/ISO Base Media File Format.

    O hitPos aponta para 'ftyp'. Verifica se os 4 bytes antes dele
    formam um box size valido e se o brand e composto por chars ASCII
    impressos.
    """
    if hit_pos < 4:
        return False

    box_size_bytes = chunk[hit_pos - 4 : hit_pos]
    box_size = struct.unpack_from(">I", box_size_bytes)[0]

    # Box size valido: entre 8 bytes (so o header) e 1 MB
    if box_size < 8 or box_size > 1 * 1024 * 1024:
        return False

    # Brand (4 bytes apos ftyp) deve ser ASCII printable
    if hit_pos + 8 > len(chunk):
        return False
    brand = chunk[hit_pos + 4 : hit_pos + 8]
    try:
        brand_str = brand.decode("ascii")
        if not brand_str.isprintable():
            return False
    except (UnicodeDecodeError, ValueError):
        return False

    return True


def _validate_pe(chunk: bytes, hit_pos: int) -> bool:
    """Validacao de cabecalho PE para reduzir falsos positivos de EXE/MZ.

    Verifica:
      1. Pelo menos 64 bytes disponiveis (tamanho minimo de um PE header)
      2. Offset 0x3C aponta para a assinatura PE
      3. Nos bytes apontados por 0x3C esta 'PE\\0\\0' (0x50 0x45 0x00 0x00)
      4. O offset 0x3C esta dentro de limites razoaveis (< 1024 bytes)
    """
    file_start = hit_pos  # hit_pos ja e a posicao do MZ no buffer

    # Precisa de pelo menos 64 bytes (offset 0x3C + 4 bytes para PE sig)
    if file_start + 64 > len(chunk):
        return False

    # Ler offset do cabecalho PE (little-endian uint32 em offset 0x3C)
    pe_offset = struct.unpack_from("<I", chunk, file_start + 0x3C)[0]

    # PE offset razoavel: deve estar entre 0x40 e 0x400 (tipicamente 0x80-0x200)
    if pe_offset < 0x40 or pe_offset > 0x400:
        return False

    # Verificar se ha espaco suficiente para a assinatura PE
    if file_start + pe_offset + 4 > len(chunk):
        return False

    # A assinatura PE deve ser 'PE\0\0'
    pe_sig = chunk[file_start + pe_offset : file_start + pe_offset + 4]
    return pe_sig == b"PE\x00\x00"


def _compute_md5(data: bytes) -> str:
    """Calcula o hash MD5 de um bloco de dados."""
    return hashlib.md5(data).hexdigest()


def _validate_file_integrity(data: bytes, sig_name: str) -> bool:
    """Validacao basica de integridade para tipos conhecidos.

    Retorna True se o arquivo passar na validacao ou se nao ha validacao
    disponivel para o tipo.
    """
    if sig_name == "PNG" and len(data) >= 8:
        expected = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
        return data[:8] == expected

    if sig_name == "PDF" and len(data) >= 4:
        return data[:4] == b"%PDF"

    if sig_name == "JPEG" and len(data) >= 3:
        return data[:3] == bytes([0xFF, 0xD8, 0xFF])

    if sig_name in ("GIF87", "GIF89") and len(data) >= 6:
        return data[:6] in (b"GIF87a", b"GIF89a")

    if sig_name == "ZIP" and len(data) >= 4:
        return data[:4] == bytes([0x50, 0x4B, 0x03, 0x04])

    if sig_name == "SQLite" and len(data) >= 16:
        return data[:16] == b"SQLite format 3\x00"

    return True


def extract_file(
    data: bytes,
    sig_name: str,
    sig: dict,
    start_in_data: int,
    output_dir: str,
    file_counter: int,
    log_lines: list[str],
    seen_hashes: set[str],
) -> tuple[int, Optional[str]]:
    """Extrai um arquivo do buffer data a partir de start_in_data.

    Retorna (bytes_consumidos, caminho_salvo ou None).
    Implementa deduplicacao via MD5 e validacao basica de integridade.
    """
    sig_offset = sig["offset"]
    file_start = start_in_data - sig_offset

    if file_start < 0:
        return 0, None

    max_size = sig["max_size"]
    footer = sig.get("footer")
    end_pos: Optional[int] = None

    chunk = data[file_start : file_start + max_size]

    # Validacao MP4 adicional (reduz falsos positivos)
    if sig.get("validate") == "mp4":
        if not _validate_mp4(chunk, start_in_data):
            return len(sig["header"]), None

    # Validacao PE adicional (reduz falsos positivos de EXE/MZ)
    if sig.get("validate") == "pe":
        if not _validate_pe(chunk, start_in_data):
            log_lines.append(
                f"[INV] {sig_name} — cabecalho PE invalido (falso positivo MZ)"
            )
            return len(sig["header"]), None

    # Verificacao secundaria (AVI/WAV)
    secondary_offset = sig.get("secondary_check_offset")
    secondary_bytes = sig.get("secondary_check")
    if secondary_offset and secondary_bytes:
        if len(chunk) < secondary_offset + len(secondary_bytes):
            return len(sig["header"]), None
        if chunk[secondary_offset : secondary_offset + len(secondary_bytes)] != secondary_bytes:
            return len(sig["header"]), None

    if footer:
        footer_pos = _find_footer(chunk, footer, len(sig["header"]))
        if footer_pos != -1:
            end_pos = footer_pos
        else:
            end_pos = min(len(chunk), max_size)
    elif sig_name == "BMP" and sig.get("size_offset") is not None:
        so = sig["size_offset"]
        sl = sig["size_length"]
        if len(chunk) >= so + sl:
            bmp_size = struct.unpack_from("<I", chunk, so)[0]
            end_pos = min(bmp_size, max_size, len(chunk))
        else:
            end_pos = min(len(chunk), max_size)
    else:
        end_pos = min(len(chunk), max_size)

    file_data = chunk[:end_pos]
    if len(file_data) < len(sig["header"]):
        return len(sig["header"]), None

    # Deduplicacao via MD5
    file_hash = _compute_md5(file_data)
    if file_hash in seen_hashes:
        log_lines.append(f"[DUP] {sig_name} duplicado (hash {file_hash[:8]}...) - ignorado")
        return end_pos, None
    seen_hashes.add(file_hash)

    # Validacao basica de integridade
    if not _validate_file_integrity(file_data, sig_name):
        log_lines.append(f"[INV] {sig_name} falhou na validacao de integridade - ignorado")
        return end_pos, None

    # Criar pasta de saida por tipo
    folder = sig.get("folder", sig_name)
    out_folder = os.path.join(output_dir, folder)
    os.makedirs(out_folder, exist_ok=True)

    ext = sig["extension"]
    filename = f"recovered_{file_counter:05d}.{ext}"
    filepath = os.path.join(out_folder, filename)

    try:
        with open(filepath, "wb") as f:
            f.write(file_data)
        log_lines.append(f"[{sig_name}] {filepath} ({format_bytes(len(file_data))})")
        return end_pos, filepath
    except Exception as e:
        log_lines.append(f"[ERRO] Nao foi possivel salvar {filepath}: {e}")
        return len(sig["header"]), None


def scan_device(
    device_path: str,
    output_dir: str,
    selected_sigs: Optional[dict[str, dict]] = None,
    limit_bytes: Optional[int] = None,
    on_progress: Optional[Callable[[int, Optional[int], int], None]] = None,
    stop_flag: Optional[list[bool]] = None,
) -> dict[str, int]:
    """Varre o dispositivo buscando arquivos por file carving.

    Args:
        device_path: caminho raw do dispositivo (ex: \\\\.\\D:)
        output_dir: pasta onde os arquivos serao salvos
        selected_sigs: dict de assinaturas (None = todas)
        limit_bytes: limitar varredura a N bytes (None = tudo)
        on_progress: callback(bytes_lidos, total_bytes, arquivos_encontrados)
        stop_flag: lista [False]; se stop_flag[0] = True, para a varredura

    Returns:
        dict {tipo: contagem}
    """
    if selected_sigs is None:
        selected_sigs = FILE_SIGNATURES

    os.makedirs(output_dir, exist_ok=True)
    log_path = get_log_path(output_dir)
    log_lines: list[str] = []
    log_lines.append("=== File Carving Recovery Log ===")
    log_lines.append(f"Inicio: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log_lines.append(f"Dispositivo: {device_path}")
    log_lines.append(f"Pasta de saida: {output_dir}")
    log_lines.append(f"Tipos buscados: {', '.join(selected_sigs.keys())}")
    log_lines.append("")

    # BUG FIX: scan_size agora e int|None, nunca causa TypeError
    from .devices import get_device_size

    total_size = get_device_size(device_path)
    if limit_bytes and total_size:
        scan_size: Optional[int] = min(limit_bytes, total_size)
    elif limit_bytes:
        scan_size = limit_bytes
    else:
        scan_size = total_size  # pode ser None

    found_counts: dict[str, int] = {name: 0 for name in selected_sigs}
    rejected_counts: dict[str, int] = {name: 0 for name in selected_sigs}
    file_counter = 0
    seen_hashes: set[str] = set()

    # BUG FIX: rastrear posicoes ja processadas entre chunks
    global_processed_up_to = 0

    log_lines.append(f"Tamanho do dispositivo: {format_bytes(total_size) if total_size else 'desconhecido'}")
    log_lines.append(f"Tamanho da varredura: {format_bytes(scan_size) if scan_size else 'desconhecido'}")
    log_lines.append("")

    try:
        f = open(device_path, "rb")
    except PermissionError:
        print("\n[ERRO] Acesso negado. Execute o programa como Administrador.")
        return found_counts
    except Exception as e:
        print(f"\n[ERRO] Nao foi possivel abrir o dispositivo: {e}")
        return found_counts

    bytes_read = 0
    leftover = b""

    sig_list_ordered = list(selected_sigs.items())

    # BUG FIX: verificar tqdm com scan_size antes de criar progress bar
    progress_bar = None
    if _HAS_TQDM and scan_size is not None:
        try:
            from tqdm import tqdm as _tqdm

            progress_bar = _tqdm(
                total=scan_size,
                unit="B",
                unit_scale=True,
                unit_divisor=1024,
                desc="Varrendo",
                ncols=80,
                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}] {postfix}",
            )
        except Exception:
            progress_bar = None

    try:
        while True:
            if stop_flag and stop_flag[0]:
                log_lines.append("Varredura interrompida pelo usuario.")
                break

            try:
                raw_chunk = f.read(CHUNK_SIZE)
            except Exception:
                try:
                    f.seek(CHUNK_SIZE, 1)
                except Exception:
                    break
                bytes_read += CHUNK_SIZE
                if progress_bar is not None:
                    progress_bar.update(CHUNK_SIZE)
                continue

            if not raw_chunk:
                break

            buffer = leftover + raw_chunk
            chunk_len = len(raw_chunk)

            # BUG FIX: rastrear posicao absoluta para evitar duplicacao
            abs_buffer_start = bytes_read - len(leftover)

            hits: list[tuple[int, str, dict]] = []
            for sig_name, sig in sig_list_ordered:
                header = sig["header"]
                search_start = 0
                while True:
                    idx = buffer.find(header, search_start)
                    if idx == -1:
                        break
                    file_start = idx - sig["offset"]
                    if file_start >= 0:
                        abs_pos = abs_buffer_start + file_start
                        if abs_pos >= global_processed_up_to:
                            hits.append((idx, sig_name, sig))
                    search_start = idx + 1

            hits.sort(key=lambda x: x[0])

            # Log detalhado: quantos hits encontrados neste chunk
            if hits:
                log_lines.append(
                    f"[CHUNK] {format_bytes(bytes_read)}: "
                    f"{len(hits)} hit(s) encontrado(s) "
                    f"({', '.join(f'{n}:{sum(1 for _,sn,_ in hits if sn==n)}' for n in dict.fromkeys(sn for _,sn,_ in hits))})"
                )

            skip_until = 0
            for hit_pos, sig_name, sig in hits:
                if hit_pos < skip_until:
                    log_lines.append(
                        f"[SKIP] {sig_name} em buffer_pos={hit_pos} "
                        f"(abs={abs_buffer_start + hit_pos}) — dentro do arquivo anterior"
                    )
                    continue
                consumed, saved_path = extract_file(
                    buffer,
                    sig_name,
                    sig,
                    hit_pos,
                    output_dir,
                    file_counter + 1,
                    log_lines,
                    seen_hashes,
                )
                if saved_path:
                    file_counter += 1
                    found_counts[sig_name] += 1
                    file_start = hit_pos - sig["offset"]
                    skip_until = file_start + consumed
                    if progress_bar is not None:
                        progress_bar.set_postfix_str(
                            f"Arquivos: {file_counter} | Ultimo: {sig_name}",
                            refresh=False,
                        )
                else:
                    rejected_counts[sig_name] = rejected_counts.get(sig_name, 0) + 1

            # BUG FIX: atualizar posicao absoluta processada
            global_processed_up_to = abs_buffer_start + len(buffer)

            leftover = buffer[-OVERLAP_SIZE:] if len(buffer) > OVERLAP_SIZE else buffer

            bytes_read += chunk_len
            if progress_bar is not None:
                progress_bar.update(chunk_len)

            if on_progress:
                on_progress(bytes_read, scan_size, file_counter)

            # BUG FIX: scan_size pode ser None — so compara se nao for
            if scan_size is not None and bytes_read >= scan_size:
                break

    except KeyboardInterrupt:
        log_lines.append("Varredura interrompida (KeyboardInterrupt).")
        if progress_bar is not None:
            progress_bar.close()
    finally:
        f.close()
        if progress_bar is not None:
            progress_bar.close()

    log_lines.append("")
    log_lines.append(f"Fim: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log_lines.append(f"Total de bytes varridos: {format_bytes(bytes_read)}")
    log_lines.append(f"Total de arquivos recuperados: {file_counter}")
    log_lines.append("")
    log_lines.append("Resumo por tipo:")
    for sig_name, count in found_counts.items():
        rejected = rejected_counts.get(sig_name, 0)
        parts = []
        if count > 0:
            parts.append(f"{count} recuperado(s)")
        if rejected > 0:
            parts.append(f"{rejected} rejeitado(s)")
        if parts:
            log_lines.append(f"  {sig_name}: {', '.join(parts)}")
    log_lines.append("")
    log_lines.append("NOTA: Arquivos pequenos (< ~700 bytes no NTFS) podem ficar")
    log_lines.append("armazenados dentro do MFT e serem perdidos na formatacao.")
    log_lines.append("Use arquivos > 1 MB para testes mais realistas.")

    write_log(log_lines, log_path)
    return found_counts
