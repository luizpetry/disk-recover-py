"""
Engine de file carving — varre dispositivos de bloco buscando assinaturas
de arquivos (magic bytes) e extraindo os arquivos encontrados.

Correcoes em relacao ao recover.py original:
  - Bug fix: scan_size=None nao causa mais TypeError no tqdm/comparacao
  - Bug fix: duplicacao por overlap buffer eliminada com rastreamento global
  - Melhoria: validacao MP4 reduz falsos positivos
  - Melhoria: deduplicacao via hash MD5
  - Melhoria: validacao basica de integridade de arquivos extraidos

Correcoes v2.1:
  - Bug fix: validadores de cabecalho (PE/BMP/MP3/MP4) recebiam a posicao do
    hit no buffer inteiro em vez da posicao dentro do chunk do arquivo,
    rejeitando arquivos reais como "falso positivo" e aceitando lixo
  - Bug fix: assinaturas sem footer nao "engolem" mais o resto do chunk —
    hits legitimos (JPEG, PNG, ...) depois delas eram descartados
  - Bug fix: extracao dedicada com handle proprio no dispositivo — arquivos
    maiores que o buffer de varredura (~1 MB) nao sao mais truncados
  - Bug fix: hits que comecam na regiao de overlap sao processados no chunk
    seguinte (antes eram marcados como processados e perdidos)
  - Melhoria: MP3_SYNC exige cadeia de frames consecutivos validos e o fim
    do MP3 e determinado seguindo a cadeia de frames
  - Melhoria: ZIP inclui o registro EOCD completo (+comentario); PDF usa o
    ultimo %%EOF (atualizacoes incrementais)
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
EXTRACT_BLOCK: int = 4 * 1024 * 1024  # 4 MB por leitura na extracao dedicada
FOOTER_CONTINUE_WINDOW: int = 2 * 1024 * 1024  # janela p/ footers subsequentes (PDF)
MP3_MIN_CHAIN_FRAMES: int = 3  # frames consecutivos exigidos para aceitar MP3_SYNC


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

    O hit_pos aponta para 'ftyp' DENTRO de chunk (chunk comeca no inicio do
    arquivo, logo hit_pos == sig['offset']). Verifica se os 4 bytes antes
    dele formam um box size valido e se o brand e composto por chars ASCII
    imprimiveis.
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

    hit_pos e a posicao do 'MZ' DENTRO de chunk (0, ja que chunk comeca no
    inicio do arquivo). Verifica:
      1. Pelo menos 64 bytes disponiveis (tamanho minimo de um PE header)
      2. Offset 0x3C aponta para a assinatura PE
      3. Nos bytes apontados por 0x3C esta 'PE\\0\\0' (0x50 0x45 0x00 0x00)
      4. O offset 0x3C esta dentro de limites razoaveis (< 1024 bytes)
    """
    file_start = hit_pos

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


def _validate_bmp(chunk: bytes, hit_pos: int) -> bool:
    """Validacao de cabecalho BMP para reduzir falsos positivos.

    hit_pos e a posicao do 'BM' DENTRO de chunk (0, ja que chunk comeca no
    inicio do arquivo). Verifica:
      1. Pelo menos 54 bytes disponiveis (header minimo BITMAPINFOHEADER)
      2. Tamanho declarado no offset 2 e razoavel (54 < size < max_size)
      3. Offset para dados de pixel (offset 10) e razoavel (54..4096)
      4. Tamanho do DIB header (offset 14) e valido (40, 52, 56, 108, 124)
      5. Bits por pixel (offset 28) e valido (1, 4, 8, 16, 24, 32)
    """
    file_start = hit_pos

    # Precisa de pelo menos 54 bytes para BITMAPINFOHEADER
    if file_start + 54 > len(chunk):
        return False

    # Tamanho declarado do arquivo (little-endian uint32 em offset 2)
    declared_size = struct.unpack_from("<I", chunk, file_start + 2)[0]

    # Tamanho razoavel: pelo menos o header (54 bytes) e no max 100 MB
    if declared_size < 54 or declared_size > 100 * 1024 * 1024:
        return False

    # Offset para dados de pixel (little-endian uint32 em offset 10)
    pixel_offset = struct.unpack_from("<I", chunk, file_start + 10)[0]

    # Offset razoavel: tipicamente 54 (24-bit) ou 1024 (256-color palette)
    if pixel_offset < 54 or pixel_offset > 4096:
        return False

    # Tamanho do DIB header (little-endian uint32 em offset 14)
    dib_header_size = struct.unpack_from("<I", chunk, file_start + 14)[0]

    # DIB header valido: BITMAPINFOHEADER(40), BITMAPV5HEADER(124), etc.
    valid_dib_sizes = {12, 40, 52, 56, 64, 108, 124}
    if dib_header_size not in valid_dib_sizes:
        return False

    # Bits por pixel (little-endian uint16 em offset 28)
    bpp = struct.unpack_from("<H", chunk, file_start + 28)[0]
    valid_bpp = {1, 4, 8, 16, 24, 32}
    if bpp not in valid_bpp:
        return False

    return True


# Tabelas MPEG-1 Layer III (unica combinacao aceita: sync 0xFF 0xFB/0xFA)
_MP3_BITRATE_KBPS = (0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0)
_MP3_SAMPLE_RATE_HZ = (44100, 48000, 32000, 0)


def _mp3_frame_length(b1: int, b2: int) -> int:
    """Tamanho do frame MPEG-1 Layer III em bytes, ou -1 se header invalido.

    b1/b2 sao o 2o e 3o bytes do frame header (o 1o e sempre 0xFF).
    """
    # b1: bits 7-5 = sync (111), bits 4-3 = versao (11 = MPEG-1),
    #     bits 2-1 = layer (01 = Layer III)
    if (b1 & 0xE0) != 0xE0 or (b1 & 0x1E) != 0x1A:
        return -1
    bitrate_index = (b2 >> 4) & 0x0F
    sample_rate_index = (b2 >> 2) & 0x03
    if bitrate_index in (0, 15) or sample_rate_index == 3:
        return -1
    bitrate = _MP3_BITRATE_KBPS[bitrate_index] * 1000
    sample_rate = _MP3_SAMPLE_RATE_HZ[sample_rate_index]
    padding = (b2 >> 1) & 0x01
    return (144 * bitrate) // sample_rate + padding


def _validate_mp3_sync(chunk: bytes, hit_pos: int) -> bool:
    """Validacao de frame header MP3 (MPEG-1 Audio Layer III).

    Um sync word de 2 bytes (0xFF 0xFB) e fraco demais sozinho — aparece o
    tempo todo em dados binarios quaisquer. Exige que uma cadeia de
    MP3_MIN_CHAIN_FRAMES frames consecutivos seja valida: o tamanho de cada
    frame e calculado pelo bitrate/sample rate do proprio header e o frame
    seguinte deve comecar exatamente onde o anterior termina.
    """
    pos = hit_pos
    for _ in range(MP3_MIN_CHAIN_FRAMES):
        if pos + 4 > len(chunk):
            return False
        if chunk[pos] != 0xFF:
            return False
        frame_len = _mp3_frame_length(chunk[pos + 1], chunk[pos + 2])
        if frame_len <= 0:
            return False
        pos += frame_len
    return True


def _validate_mp3_id3(chunk: bytes, hit_pos: int) -> bool:
    """Validacao de cabecalho ID3v2.

    hit_pos e a posicao do 'ID3' DENTRO de chunk (0, ja que chunk comeca no
    inicio do arquivo). Verifica:
      1. Pelo menos 10 bytes disponiveis (header ID3v2 = 10 bytes)
      2. Byte 3 (versao major): 2, 3 ou 4 (ID3v2.2, v2.3, v2.4)
      3. Bytes 6-9 (tamanho syncsafe): cada byte deve ter bit 7 = 0
      4. Tamanho total > 0
    """
    file_start = hit_pos

    # Precisa de pelo menos 10 bytes para o header ID3v2
    if file_start + 10 > len(chunk):
        return False

    # Versao major (byte 3): deve ser 2, 3 ou 4
    version_major = chunk[file_start + 3]
    if version_major not in (2, 3, 4):
        return False

    # Tamanho syncsafe (bytes 6-9): cada byte usa 7 bits, bit 7 sempre 0
    for i in range(6, 10):
        if chunk[file_start + i] & 0x80:
            return False

    # Tamanho total deve ser > 0
    size = (
        ((chunk[file_start + 6] & 0x7F) << 21)
        | ((chunk[file_start + 7] & 0x7F) << 14)
        | ((chunk[file_start + 8] & 0x7F) << 7)
        | (chunk[file_start + 9] & 0x7F)
    )
    if size == 0:
        return False

    return True


def _validate_jpeg(chunk: bytes, hit_pos: int) -> bool:
    """Validacao estrutural de JPEG: percorre os marcadores ate o SOS.

    Comecar com FF D8 FF nao basta (tabelas de bytes/valores Unicode
    contem essa sequencia): um JPEG real tem segmentos validos (APPn,
    DQT, SOF, ...) entre o SOI e o SOS (inicio dos dados comprimidos).
    """
    pos = hit_pos + 2  # apos o SOI (FF D8)
    segments = 0
    while pos + 4 <= len(chunk) and segments < 64:
        if chunk[pos] != 0xFF:
            return False
        marker = chunk[pos + 1]
        if marker == 0xFF:
            pos += 1  # fill byte
            continue
        if marker in (0xD8, 0xD9):
            return False  # SOI duplicado ou EOI antes de qualquer dado
        if 0xD0 <= marker <= 0xD7:
            return False  # RST fora da area comprimida
        if marker == 0xDA:
            return segments >= 1  # SOS valido apos pelo menos 1 segmento
        seg_len = (chunk[pos + 2] << 8) | chunk[pos + 3]
        if seg_len < 2:
            return False
        pos += 2 + seg_len
        segments += 1
    return False


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


# ---------------------------------------------------------------------------
# Leitura dedicada no dispositivo (extracao alem do buffer de varredura)
# ---------------------------------------------------------------------------

def _read_at(fh, abs_pos: int, length: int) -> bytes:
    """Le `length` bytes na posicao absoluta `abs_pos` do dispositivo.

    Dispositivos raw no Windows exigem seek e leitura alinhados a setor:
    alinha o inicio para baixo, arredonda o tamanho para cima e descarta
    o excedente.
    """
    if length <= 0:
        return b""
    aligned_start = (abs_pos // SECTOR_SIZE) * SECTOR_SIZE
    delta = abs_pos - aligned_start
    total = delta + length
    remainder = total % SECTOR_SIZE
    if remainder:
        total += SECTOR_SIZE - remainder
    try:
        fh.seek(aligned_start)
    except Exception:
        return b""
    parts: list[bytes] = []
    remaining = total
    while remaining > 0:
        try:
            block = fh.read(remaining)
        except Exception:
            break
        if not block:
            break
        parts.append(block)
        remaining -= len(block)
    data = b"".join(parts)
    return data[delta : delta + length]


def _carve_with_footer(fh, abs_file_start: int, sig: dict) -> tuple[Optional[bytes], bool]:
    """Le do dispositivo a partir de abs_file_start ate localizar o footer.

    Diferente da busca no buffer de varredura, nao ha o limite de ~1 chunk:
    le blocos progressivamente ate sig['max_size']. Retorna (dados, True)
    quando o footer foi encontrado; (None, False) caso contrario.
    """
    footer: bytes = sig["footer"]
    max_size: int = sig["max_size"]
    take_last = sig.get("footer_search") == "last"
    footer_extra: int = sig.get("footer_extra", 0)
    min_start = sig["offset"] + len(sig["header"])

    data = bytearray()
    scanned = min_start  # ate onde a busca por footer ja foi feita
    last_end = -1  # fim (exclusivo) do arquivo apos o ultimo footer visto

    while len(data) < max_size:
        want = min(EXTRACT_BLOCK, max_size - len(data))
        block = _read_at(fh, abs_file_start + len(data), want)
        if not block:
            break
        data += block

        # Sobreposicao de len(footer)-1 cobre footer partido entre blocos
        pos = max(scanned - (len(footer) - 1), min_start)
        while True:
            idx = data.find(footer, pos)
            if idx == -1:
                break
            last_end = idx + len(footer) + footer_extra
            pos = idx + 1
            if not take_last:
                break
        scanned = len(data)

        if last_end != -1:
            if not take_last:
                break
            # Modo "last" (PDF): para quando nenhum footer novo aparece
            # dentro da janela apos o ultimo encontrado
            if len(data) - last_end >= FOOTER_CONTINUE_WINDOW:
                break

        if len(block) < want:
            break  # fim do dispositivo

    if last_end == -1:
        return None, False

    end = min(last_end, max_size)
    if end > len(data):
        extra = _read_at(fh, abs_file_start + len(data), end - len(data))
        data += extra
        end = min(end, len(data))

    # ZIP: o registro EOCD pode ter comentario (tamanho nos 2 ultimos bytes)
    if sig.get("footer_kind") == "zip_eocd":
        rec_start = end - 22
        if rec_start >= 0 and rec_start + 22 <= len(data):
            comment_len = int.from_bytes(data[rec_start + 20 : rec_start + 22], "little")
            if comment_len:
                new_end = min(end + comment_len, max_size)
                if new_end > len(data):
                    extra = _read_at(fh, abs_file_start + len(data), new_end - len(data))
                    data += extra
                end = min(new_end, len(data))

    return bytes(data[:end]), True


def _carve_mp3_stream(
    fh, abs_file_start: int, max_size: int, start_pos: int
) -> tuple[Optional[bytes], bool]:
    """Segue a cadeia de frames MP3 a partir de start_pos ate ela quebrar.

    start_pos > 0 quando ha tag ID3v2 no inicio (o audio comeca depois dela).
    Retorna (dados ate o fim do ultimo frame valido, True) ou (None, False).
    """
    sync_search_window = 2048  # tolera padding entre a tag ID3 e o 1o frame

    if start_pos >= max_size:
        return None, False

    data = bytearray()

    def ensure(n: int) -> bool:
        while len(data) < n and len(data) < max_size:
            want = min(EXTRACT_BLOCK, max_size - len(data))
            block = _read_at(fh, abs_file_start + len(data), want)
            if not block:
                break
            data.extend(block)
            if len(block) < want:
                break
        return len(data) >= n

    # Localiza o primeiro frame sync a partir de start_pos
    ensure(start_pos + sync_search_window)
    pos = -1
    for i in range(start_pos, min(start_pos + sync_search_window, len(data) - 3)):
        if data[i] == 0xFF and _mp3_frame_length(data[i + 1], data[i + 2]) > 0:
            pos = i
            break
    if pos == -1:
        return None, False

    frames = 0
    while True:
        if not ensure(pos + 4):
            break
        if data[pos] != 0xFF:
            break
        frame_len = _mp3_frame_length(data[pos + 1], data[pos + 2])
        if frame_len <= 0 or pos + frame_len > max_size:
            break
        pos += frame_len
        frames += 1

    if frames == 0:
        return None, False

    end = min(pos, len(data))
    return bytes(data[:end]), True


def extract_file(
    data: bytes,
    sig_name: str,
    sig: dict,
    start_in_data: int,
    abs_file_start: int,
    extract_handle,
    output_dir: str,
    file_counter: int,
    log_lines: list[str],
    seen_hashes: set[str],
) -> tuple[int, Optional[str], bool]:
    """Extrai um arquivo a partir do hit em start_in_data.

    `data` e o buffer de varredura (usado para validacoes e como fallback);
    quando `extract_handle` esta disponivel, o conteudo completo e lido
    diretamente do dispositivo a partir de `abs_file_start`, sem o limite
    do buffer (BUG FIX: antes arquivos > ~1 MB saiam truncados).

    Retorna (bytes_consumidos, caminho_salvo ou None, fim_confiavel):
      - bytes_consumidos: tamanho do arquivo relativo ao inicio dele
        (ou len(header) quando o hit foi rejeitado)
      - fim_confiavel: True quando o fim foi determinado por footer,
        tamanho declarado ou cadeia de frames (nao por corte arbitrario)
    """
    sig_offset = sig["offset"]
    header_len = len(sig["header"])
    file_start = start_in_data - sig_offset

    if file_start < 0:
        return 0, None, False

    max_size = sig["max_size"]
    footer = sig.get("footer")

    chunk = data[file_start : file_start + max_size]

    # BUG FIX: os validadores recebem a posicao do header DENTRO de chunk.
    # chunk comeca no inicio do arquivo, logo o header esta em sig_offset —
    # antes era passado start_in_data (posicao no buffer inteiro), fazendo a
    # validacao ler bytes aleatorios: arquivos reais eram rejeitados como
    # "falso positivo" e lixo era aceito.
    if sig.get("validate") == "mp4":
        if not _validate_mp4(chunk, sig_offset):
            return header_len, None, False

    if sig.get("validate") == "pe":
        if not _validate_pe(chunk, sig_offset):
            log_lines.append(
                f"[INV] {sig_name} — cabecalho PE invalido (falso positivo MZ)"
            )
            return header_len, None, False

    if sig.get("validate") == "bmp":
        if not _validate_bmp(chunk, sig_offset):
            log_lines.append(
                f"[INV] {sig_name} — cabecalho BMP invalido (falso positivo)"
            )
            return header_len, None, False

    if sig.get("validate") == "jpeg":
        if not _validate_jpeg(chunk, sig_offset):
            log_lines.append(
                f"[INV] {sig_name} — estrutura de marcadores invalida (falso positivo)"
            )
            return header_len, None, False

    # MP3_SYNC rejeitado nao gera log: 0xFF 0xFB e frequente em dados
    # binarios e o log ficaria inundado
    if sig.get("validate") == "mp3_sync":
        if not _validate_mp3_sync(chunk, sig_offset):
            return header_len, None, False

    if sig.get("validate") == "mp3_id3":
        if not _validate_mp3_id3(chunk, sig_offset):
            log_lines.append(
                f"[INV] {sig_name} — cabecalho ID3v2 invalido (versao/tamanho invalido)"
            )
            return header_len, None, False

    # Verificacao secundaria (AVI/WAV)
    secondary_offset = sig.get("secondary_check_offset")
    secondary_bytes = sig.get("secondary_check")
    if secondary_offset and secondary_bytes:
        if len(chunk) < secondary_offset + len(secondary_bytes):
            return header_len, None, False
        if chunk[secondary_offset : secondary_offset + len(secondary_bytes)] != secondary_bytes:
            return header_len, None, False

    # Determinar o conteudo e o fim do arquivo
    file_data: Optional[bytes] = None
    end_reliable = False

    if footer:
        if extract_handle is not None:
            carved, found = _carve_with_footer(extract_handle, abs_file_start, sig)
            if found and carved:
                file_data = carved
                end_reliable = True
        if file_data is None:
            # Fallback: busca limitada ao buffer de varredura
            footer_pos = _find_footer(chunk, footer, sig_offset + header_len)
            if footer_pos != -1:
                end = min(footer_pos + sig.get("footer_extra", 0), len(chunk))
                file_data = chunk[:end]
                end_reliable = True
            else:
                file_data = chunk  # truncado no fim do buffer
    elif sig.get("carve") == "mp3" and extract_handle is not None:
        start_pos = 0
        if sig_name == "MP3_ID3" and len(chunk) >= 10:
            tag_size = (
                ((chunk[6] & 0x7F) << 21)
                | ((chunk[7] & 0x7F) << 14)
                | ((chunk[8] & 0x7F) << 7)
                | (chunk[9] & 0x7F)
            )
            start_pos = 10 + tag_size
        carved, found = _carve_mp3_stream(extract_handle, abs_file_start, max_size, start_pos)
        if found and carved:
            file_data = carved
            end_reliable = True
        else:
            file_data = chunk
    elif sig.get("size_offset") is not None:
        so = sig["size_offset"]
        sl = sig["size_length"]
        if len(chunk) >= so + sl:
            declared = struct.unpack_from("<I", chunk, so)[0]
            declared = min(declared, max_size)
            if declared > len(chunk) and extract_handle is not None:
                carved_data = _read_at(extract_handle, abs_file_start, declared)
                if len(carved_data) == declared:
                    file_data = carved_data
                    end_reliable = True
                else:
                    file_data = chunk
            else:
                file_data = chunk[:declared]
                end_reliable = declared <= len(chunk)
        else:
            file_data = chunk
    else:
        # Sem footer nem tamanho declarado: salva o que ha no buffer, mas
        # sinaliza fim NAO confiavel — o chamador nao deve bloquear hits
        # seguintes por causa deste arquivo (BUG FIX: antes o resto do chunk
        # inteiro era marcado como consumido, engolindo arquivos reais)
        file_data = chunk

    if file_data is None or len(file_data) < sig_offset + header_len:
        return header_len, None, False

    # Filtro de tamanho minimo (filtra icons, thumbnails e miniaturas do sistema)
    min_size = sig.get("min_size", 0)
    if min_size and len(file_data) < min_size:
        log_lines.append(
            f"[TINY] {sig_name} — {len(file_data)} bytes < minimo {min_size} bytes (rejeitado)"
        )
        return header_len, None, False

    consumed = len(file_data)

    # Deduplicacao via MD5
    file_hash = _compute_md5(file_data)
    if file_hash in seen_hashes:
        log_lines.append(f"[DUP] {sig_name} duplicado (hash {file_hash[:8]}...) - ignorado")
        if end_reliable:
            return consumed, None, True
        return header_len, None, False
    seen_hashes.add(file_hash)

    # Validacao basica de integridade
    if not _validate_file_integrity(file_data, sig_name):
        log_lines.append(f"[INV] {sig_name} falhou na validacao de integridade - ignorado")
        return header_len, None, False

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
        return consumed, filepath, end_reliable
    except Exception as e:
        log_lines.append(f"[ERRO] Nao foi possivel salvar {filepath}: {e}")
        return header_len, None, False


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
    total_hits_found = 0  # Total de hits encontrados em todos os chunks
    chunks_with_hits = 0  # Quantos chunks tiveram pelo menos 1 hit
    last_log_mb = 0  # Para logging periodico em discos grandes

    # BUG FIX: rastrear posicoes ja processadas entre chunks
    global_processed_up_to = 0

    # Fim confiavel (footer/tamanho declarado): pula QUALQUER hit dentro do
    # arquivo ja extraido. Fim incerto: pula apenas hits da MESMA assinatura
    # dentro do trecho salvo (nao engole arquivos reais de outros tipos).
    abs_skip_all_until = 0
    abs_skip_sig_until: dict[str, int] = {}

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

    # BUG FIX: handle dedicado para extracao — permite ler o arquivo completo
    # a partir de qualquer posicao absoluta, sem o limite do buffer de
    # varredura. buffering=0 mantem as leituras alinhadas a setor.
    try:
        extract_handle = open(device_path, "rb", buffering=0)
    except Exception:
        extract_handle = None
        log_lines.append(
            "[AVISO] Nao foi possivel abrir handle de extracao dedicado; "
            "arquivos ficarao limitados ao buffer de varredura (~1 MB)."
        )

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
                # BUG FIX: os dados apos o trecho ilegivel nao sao contiguos
                # ao leftover antigo — descarta para nao costurar dados errados
                leftover = b""
                if progress_bar is not None:
                    progress_bar.update(CHUNK_SIZE)
                continue

            eof = not raw_chunk
            if eof and not leftover:
                break

            # No EOF ainda processamos o leftover final: ele contem os hits
            # que foram deferidos da regiao de overlap do chunk anterior
            buffer = leftover if eof else leftover + raw_chunk
            chunk_len = 0 if eof else len(raw_chunk)

            # BUG FIX: rastrear posicao absoluta para evitar duplicacao
            abs_buffer_start = bytes_read - len(leftover)

            # Ultimo chunk? (fim do dispositivo ou limite de varredura)
            is_last = eof or chunk_len < CHUNK_SIZE or (
                scan_size is not None and bytes_read + chunk_len >= scan_size
            )

            # BUG FIX: hits que comecam na regiao de overlap sao deixados
            # para o proximo chunk (quando havera mais dados adiante); antes
            # eram marcados como processados sem nunca serem extraidos
            if is_last or len(buffer) <= OVERLAP_SIZE:
                scan_limit = len(buffer)
            else:
                scan_limit = len(buffer) - OVERLAP_SIZE

            hits: list[tuple[int, str, dict]] = []
            for sig_name, sig in sig_list_ordered:
                header = sig["header"]
                search_start = 0
                while True:
                    idx = buffer.find(header, search_start)
                    if idx == -1:
                        break
                    file_start = idx - sig["offset"]
                    if 0 <= file_start < scan_limit:
                        abs_pos = abs_buffer_start + file_start
                        if abs_pos >= global_processed_up_to:
                            hits.append((idx, sig_name, sig))
                    search_start = idx + 1

            hits.sort(key=lambda x: x[0])

            # Log detalhado: quantos hits encontrados neste chunk
            if hits:
                total_hits_found += len(hits)
                chunks_with_hits += 1
                log_lines.append(
                    f"[CHUNK] {format_bytes(bytes_read)}: "
                    f"{len(hits)} hit(s) encontrado(s) "
                    f"({', '.join(f'{n}:{sum(1 for _,sn,_ in hits if sn==n)}' for n in dict.fromkeys(sn for _,sn,_ in hits))})"
                )

            # Log periodico para discos grandes (a cada 500 MB sem hits)
            current_mb = bytes_read // (500 * 1024 * 1024)
            if not hits and current_mb > last_log_mb:
                last_log_mb = current_mb
                log_lines.append(
                    f"[SCAN] {format_bytes(bytes_read)} varridos — "
                    f"{total_hits_found} hits totais, {file_counter} arquivos"
                )

            skipped_same_sig = 0
            for hit_pos, sig_name, sig in hits:
                file_start = hit_pos - sig["offset"]
                abs_file_start = abs_buffer_start + file_start

                if abs_file_start < abs_skip_all_until:
                    log_lines.append(
                        f"[SKIP] {sig_name} em abs={abs_file_start} "
                        f"— dentro do arquivo anterior"
                    )
                    continue
                if abs_file_start < abs_skip_sig_until.get(sig_name, 0):
                    skipped_same_sig += 1
                    continue

                consumed, saved_path, end_reliable = extract_file(
                    buffer,
                    sig_name,
                    sig,
                    hit_pos,
                    abs_file_start,
                    extract_handle,
                    output_dir,
                    file_counter + 1,
                    log_lines,
                    seen_hashes,
                )
                if saved_path:
                    file_counter += 1
                    found_counts[sig_name] += 1
                    if progress_bar is not None:
                        progress_bar.set_postfix_str(
                            f"Arquivos: {file_counter} | Ultimo: {sig_name}",
                            refresh=False,
                        )
                else:
                    rejected_counts[sig_name] = rejected_counts.get(sig_name, 0) + 1

                # BUG FIX: hits seguintes so sao bloqueados quando o fim do
                # arquivo e confiavel; com fim incerto, bloqueia apenas a
                # mesma assinatura (falsos positivos nao engolem mais os
                # arquivos reais que vem depois no chunk)
                if end_reliable:
                    abs_skip_all_until = max(
                        abs_skip_all_until, abs_file_start + consumed
                    )
                elif saved_path:
                    abs_skip_sig_until[sig_name] = max(
                        abs_skip_sig_until.get(sig_name, 0),
                        abs_file_start + consumed,
                    )

            if skipped_same_sig:
                log_lines.append(
                    f"[SKIP] {skipped_same_sig} hit(s) da mesma assinatura "
                    f"dentro de trecho ja salvo"
                )

            # Marca como processado apenas ate scan_limit; a regiao de
            # overlap sera varrida novamente no proximo chunk
            global_processed_up_to = abs_buffer_start + scan_limit

            if eof:
                break

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
        if extract_handle is not None:
            extract_handle.close()
        if progress_bar is not None:
            progress_bar.close()

    log_lines.append("")
    log_lines.append(f"Fim: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log_lines.append(f"Total de bytes varridos: {format_bytes(bytes_read)}")
    log_lines.append(f"Total de hits encontrados: {total_hits_found}")
    log_lines.append(f"Chunks com hits: {chunks_with_hits}")
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
    log_lines.append("armazenados dentro do MFT e serem perdidos na formatacao rapida.")
    log_lines.append("Para testes, use arquivos > 1 MB.")

    write_log(log_lines, log_path)
    return found_counts
