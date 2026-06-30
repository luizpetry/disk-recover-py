"""
File Carving Recovery Tool
Recupera arquivos de discos/pendrives formatados buscando por magic bytes nos setores brutos.
Requer execucao como Administrador no Windows.
Dependencia: pip install tqdm
"""

import os
import sys
import struct
import ctypes
import datetime
import platform
import time

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False


# =============================================================================
# ASSINATURAS DE ARQUIVOS (magic bytes)
# =============================================================================
# Cada entrada: (header_bytes, header_offset, extensao, tamanho_max, footer_bytes ou None)
# tamanho_max em bytes. footer_bytes: buscar este padrao para saber onde o arquivo termina.

FILE_SIGNATURES = {
    "JPEG": {
        "header": bytes([0xFF, 0xD8, 0xFF]),
        "offset": 0,
        "extension": "jpg",
        "max_size": 15 * 1024 * 1024,       # 15 MB
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
        "size_offset": 2,   # campo de tamanho no header BMP (little-endian uint32 em offset 2)
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


# =============================================================================
# UTILITARIOS
# =============================================================================

def is_windows():
    return platform.system() == "Windows"


def is_admin():
    if is_windows():
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.geteuid() == 0


def clear_screen():
    os.system("cls" if is_windows() else "clear")


def format_bytes(size):
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"


def get_device_size(device_path):
    """Tenta obter o tamanho total do dispositivo em bytes."""
    try:
        if is_windows():
            import ctypes
            GENERIC_READ = 0x80000000
            FILE_SHARE_READ = 0x00000001
            FILE_SHARE_WRITE = 0x00000002
            OPEN_EXISTING = 3
            IOCTL_DISK_GET_DRIVE_GEOMETRY_EX = 0x000700A0

            handle = ctypes.windll.kernel32.CreateFileW(
                device_path,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                0,
                None
            )
            if handle == ctypes.c_void_p(-1).value:
                return None

            class DISK_GEOMETRY(ctypes.Structure):
                _fields_ = [
                    ("Cylinders", ctypes.c_int64),
                    ("MediaType", ctypes.c_uint),
                    ("TracksPerCylinder", ctypes.c_ulong),
                    ("SectorsPerTrack", ctypes.c_ulong),
                    ("BytesPerSector", ctypes.c_ulong),
                ]

            class DISK_GEOMETRY_EX(ctypes.Structure):
                _fields_ = [
                    ("Geometry", DISK_GEOMETRY),
                    ("DiskSize", ctypes.c_int64),
                    ("Data", ctypes.c_byte * 1),
                ]

            geo = DISK_GEOMETRY_EX()
            bytes_returned = ctypes.c_ulong(0)
            result = ctypes.windll.kernel32.DeviceIoControl(
                handle,
                IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                None, 0,
                ctypes.byref(geo), ctypes.sizeof(geo),
                ctypes.byref(bytes_returned),
                None
            )
            ctypes.windll.kernel32.CloseHandle(handle)
            if result:
                return geo.DiskSize
            return None
        else:
            with open(device_path, "rb") as f:
                f.seek(0, 2)
                return f.tell()
    except Exception:
        return None


# =============================================================================
# LISTAGEM DE DISPOSITIVOS
# =============================================================================

def list_drives_windows():
    """Lista drives logicos e discos fisicos no Windows."""
    drives = []

    # Drives logicos (letras)
    drive_bits = ctypes.windll.kernel32.GetLogicalDrives()
    for i in range(26):
        if drive_bits & (1 << i):
            letter = chr(ord("A") + i)
            drive_path = f"{letter}:\\"
            raw_path = f"\\\\.\\{letter}:"

            drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive_path)
            # 2=REMOVABLE, 3=FIXED, 4=REMOTE, 5=CDROM, 6=RAMDISK
            type_names = {2: "Removivel", 3: "Fixo", 4: "Rede", 5: "CD/DVD", 6: "RAM"}
            type_str = type_names.get(drive_type, "Desconhecido")

            size = get_device_size(raw_path)
            size_str = format_bytes(size) if size else "Tamanho desconhecido"

            drives.append({
                "label": f"{letter}: ({type_str}) - {size_str}",
                "path": raw_path,
                "type": type_str,
                "size": size,
            })

    # Discos fisicos (PhysicalDrive)
    for i in range(10):
        phys_path = f"\\\\.\\PhysicalDrive{i}"
        size = get_device_size(phys_path)
        if size is not None:
            drives.append({
                "label": f"PhysicalDrive{i} (Disco Fisico) - {format_bytes(size)}",
                "path": phys_path,
                "type": "Fisico",
                "size": size,
            })

    return drives


def list_drives_linux():
    """Lista dispositivos de bloco no Linux."""
    drives = []
    dev_dir = "/dev"
    try:
        for name in sorted(os.listdir(dev_dir)):
            if name.startswith(("sd", "hd", "nvme", "vd", "xvd", "mmcblk")):
                # Apenas dispositivos raiz (nao particoes como sda1)
                if any(c.isdigit() for c in name) and not name.startswith("nvme"):
                    continue
                full_path = os.path.join(dev_dir, name)
                size = get_device_size(full_path)
                size_str = format_bytes(size) if size else "Tamanho desconhecido"
                drives.append({
                    "label": f"{full_path} - {size_str}",
                    "path": full_path,
                    "type": "Bloco",
                    "size": size,
                })
    except Exception as e:
        print(f"Erro ao listar dispositivos: {e}")
    return drives


def list_drives():
    if is_windows():
        return list_drives_windows()
    else:
        return list_drives_linux()


# =============================================================================
# ENGINE DE FILE CARVING
# =============================================================================

CHUNK_SIZE = 1 * 1024 * 1024      # 1 MB por leitura
SECTOR_SIZE = 512
MAX_HEADER_LEN = 32               # maior magic bytes que usamos
OVERLAP_SIZE = 65536              # 64 KB de sobreposicao entre chunks


def find_footer(data, footer_bytes, start_pos=0):
    """Busca footer_bytes em data a partir de start_pos. Retorna posicao do fim do footer ou -1."""
    idx = data.find(footer_bytes, start_pos)
    if idx == -1:
        return -1
    return idx + len(footer_bytes)


def extract_file(data, sig_name, sig, start_in_data, output_dir, file_counter, log_lines):
    """
    Extrai um arquivo do buffer data a partir de start_in_data.
    Retorna (bytes_consumidos, caminho_salvo ou None).
    """
    sig_offset = sig["offset"]
    # start_in_data ja aponta para onde o magic byte comeca (considerando o offset do sig)
    file_start = start_in_data - sig_offset  # inicio real do arquivo no buffer

    if file_start < 0:
        return 0, None

    max_size = sig["max_size"]
    footer = sig.get("footer")
    end_pos = None

    chunk = data[file_start: file_start + max_size]

    # Verificacao secundaria (AVI/WAV)
    secondary_offset = sig.get("secondary_check_offset")
    secondary_bytes = sig.get("secondary_check")
    if secondary_offset and secondary_bytes:
        if len(chunk) < secondary_offset + len(secondary_bytes):
            return len(sig["header"]), None
        if chunk[secondary_offset: secondary_offset + len(secondary_bytes)] != secondary_bytes:
            return len(sig["header"]), None

    if footer:
        footer_pos = find_footer(chunk, footer, len(sig["header"]))
        if footer_pos != -1:
            end_pos = footer_pos
        else:
            # Footer nao encontrado no buffer atual — usar limite maximo
            end_pos = min(len(chunk), max_size)
    elif sig_name == "BMP" and sig.get("size_offset") is not None:
        # Tamanho embutido no header BMP
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


def scan_device(device_path, output_dir, selected_sigs=None, limit_bytes=None,
                on_progress=None, stop_flag=None):
    """
    Varre o dispositivo buscando arquivos por file carving.

    Parametros:
        device_path: caminho raw do dispositivo (ex: \\\\.\\D:)
        output_dir: pasta onde os arquivos serao salvos
        selected_sigs: dict de assinaturas (None = todas)
        limit_bytes: limitar varredura a N bytes (None = tudo)
        on_progress: callback(bytes_lidos, total_bytes, arquivos_encontrados)
        stop_flag: lista [False]; se stop_flag[0] = True, para a varredura

    Retorna: dict {tipo: contagem}
    """
    if selected_sigs is None:
        selected_sigs = FILE_SIGNATURES

    os.makedirs(output_dir, exist_ok=True)
    log_path = os.path.join(output_dir, "recovery_log.txt")
    log_lines = []
    log_lines.append(f"=== File Carving Recovery Log ===")
    log_lines.append(f"Inicio: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log_lines.append(f"Dispositivo: {device_path}")
    log_lines.append(f"Pasta de saida: {output_dir}")
    log_lines.append(f"Tipos buscados: {', '.join(selected_sigs.keys())}")
    log_lines.append("")

    total_size = get_device_size(device_path)
    if limit_bytes and total_size:
        scan_size = min(limit_bytes, total_size)
    elif limit_bytes:
        scan_size = limit_bytes
    else:
        scan_size = total_size  # pode ser None

    found_counts = {name: 0 for name in selected_sigs}
    file_counter = 0

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

    # Lista ordenada de (sig_name, sig) para varredura consistente
    sig_list_ordered = list(selected_sigs.items())

    progress_bar = None
    if TQDM_AVAILABLE and scan_size:
        progress_bar = tqdm(
            total=scan_size,
            unit="B",
            unit_scale=True,
            unit_divisor=1024,
            desc="Varrendo",
            ncols=80,
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}] {postfix}"
        )

    try:
        while True:
            if stop_flag and stop_flag[0]:
                log_lines.append("Varredura interrompida pelo usuario.")
                break

            try:
                raw_chunk = f.read(CHUNK_SIZE)
            except Exception as e:
                # Erro de leitura (setor ruim): tentar pular
                try:
                    f.seek(CHUNK_SIZE, 1)
                except Exception:
                    break
                bytes_read += CHUNK_SIZE
                if progress_bar:
                    progress_bar.update(CHUNK_SIZE)
                continue

            if not raw_chunk:
                break

            # Combinar leftover do chunk anterior com chunk atual
            # O leftover garante que assinaturas na borda entre chunks nao sejam perdidas
            buffer = leftover + raw_chunk
            chunk_len = len(raw_chunk)

            # Para cada tipo de assinatura, encontrar todas as ocorrencias no buffer
            # e registrar (posicao, sig_name, sig) numa lista para processar em ordem
            hits = []
            for sig_name, sig in sig_list_ordered:
                header = sig["header"]
                search_start = 0
                while True:
                    idx = buffer.find(header, search_start)
                    if idx == -1:
                        break
                    # Para sigs com offset (ex: MP4 ftyp em offset 4),
                    # o "idx" encontrado e a posicao do magic, nao do inicio do arquivo.
                    # file_start = idx - offset; se file_start < 0 ignora.
                    file_start = idx - sig["offset"]
                    if file_start >= 0:
                        hits.append((idx, sig_name, sig))
                    search_start = idx + 1

            # Ordenar hits por posicao crescente
            hits.sort(key=lambda x: x[0])

            # Processar hits sem sobreposicao: ao extrair um arquivo,
            # pular hits que caiam dentro do arquivo extraido
            skip_until = 0
            for hit_pos, sig_name, sig in hits:
                if hit_pos < skip_until:
                    continue
                consumed, saved_path = extract_file(
                    buffer, sig_name, sig, hit_pos,
                    output_dir, file_counter + 1, log_lines
                )
                if saved_path:
                    file_counter += 1
                    found_counts[sig_name] += 1
                    file_start = hit_pos - sig["offset"]
                    skip_until = file_start + consumed
                    if progress_bar:
                        progress_bar.set_postfix_str(
                            f"Arquivos: {file_counter} | Ultimo: {sig_name}",
                            refresh=False
                        )

            # Guardar os ultimos OVERLAP_SIZE bytes para o proximo chunk
            leftover = buffer[-OVERLAP_SIZE:] if len(buffer) > OVERLAP_SIZE else buffer

            bytes_read += chunk_len
            if progress_bar:
                progress_bar.update(chunk_len)

            if on_progress:
                on_progress(bytes_read, scan_size, file_counter)

            if scan_size and bytes_read >= scan_size:
                break

    except KeyboardInterrupt:
        log_lines.append("Varredura interrompida (KeyboardInterrupt).")
        if progress_bar:
            progress_bar.close()
    finally:
        f.close()
        if progress_bar:
            progress_bar.close()

    log_lines.append("")
    log_lines.append(f"Fim: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log_lines.append(f"Total de bytes varridos: {format_bytes(bytes_read)}")
    log_lines.append(f"Total de arquivos recuperados: {file_counter}")
    log_lines.append("")
    log_lines.append("Resumo por tipo:")
    for sig_name, count in found_counts.items():
        if count > 0:
            log_lines.append(f"  {sig_name}: {count}")

    try:
        with open(log_path, "w", encoding="utf-8") as lf:
            lf.write("\n".join(log_lines))
    except Exception:
        pass

    return found_counts


# =============================================================================
# CLI INTERATIVA
# =============================================================================

DEFAULT_OUTPUT_DIR = "C:\\Recovered_Files" if is_windows() else os.path.expanduser("~/Recovered_Files")


def print_header():
    print("=" * 60)
    print("   FILE CARVING RECOVERY TOOL")
    print("   Recuperacao de arquivos por varredura de blocos brutos")
    print("=" * 60)
    print()


def print_admin_warning():
    if not is_admin():
        print("  [!] ATENCAO: Este programa NAO esta rodando como Administrador.")
        print("      Acesso raw ao disco pode falhar sem permissoes elevadas.")
        print("      Recomendado: clique direito no terminal > 'Executar como Administrador'")
        print()


def menu_principal(config):
    while True:
        clear_screen()
        print_header()
        print_admin_warning()
        print(f"  Pasta de saida atual: {config['output_dir']}")
        print(f"  Limite de varredura:  {format_bytes(config['limit_bytes']) if config['limit_bytes'] else 'Sem limite (disco inteiro)'}")
        print()
        print("  [1] Listar dispositivos disponiveis")
        print("  [2] Iniciar recuperacao de arquivos")
        print("  [3] Configuracoes")
        print("  [4] Sair")
        print()
        choice = input("  Escolha uma opcao: ").strip()

        if choice == "1":
            menu_listar_dispositivos()
        elif choice == "2":
            menu_recuperacao(config)
        elif choice == "3":
            menu_configuracoes(config)
        elif choice == "4":
            print("\n  Encerrando. Ate logo!")
            sys.exit(0)
        else:
            print("  Opcao invalida. Pressione Enter para continuar.")
            input()


def menu_listar_dispositivos():
    clear_screen()
    print_header()
    print("  Buscando dispositivos...\n")
    drives = list_drives()

    if not drives:
        print("  Nenhum dispositivo encontrado.")
    else:
        print(f"  {'#':<4} {'Dispositivo':<55} {'Path'}")
        print(f"  {'-'*4} {'-'*55} {'-'*30}")
        for i, d in enumerate(drives, 1):
            print(f"  {i:<4} {d['label']:<55} {d['path']}")
    print()
    input("  Pressione Enter para voltar ao menu principal.")


def menu_selecionar_tipos():
    """Retorna dict de assinaturas selecionadas pelo usuario."""
    clear_screen()
    print_header()
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

    selected = {}
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


def menu_recuperacao(config):
    clear_screen()
    print_header()

    # 1) Listar e selecionar dispositivo
    print("  Buscando dispositivos...\n")
    drives = list_drives()

    if not drives:
        print("  Nenhum dispositivo encontrado. Verifique as permissoes.")
        input("  Pressione Enter para voltar.")
        return

    print(f"  {'#':<4} {'Dispositivo'}")
    print(f"  {'-'*4} {'-'*60}")
    for i, d in enumerate(drives, 1):
        print(f"  {i:<4} {d['label']}")
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
    device_path = selected_drive["path"]

    # 2) Confirmar pasta de saida
    print(f"\n  Pasta de saida padrao: {config['output_dir']}")
    custom = input("  Pressione Enter para usar o padrao ou digite outro caminho: ").strip()
    output_dir = custom if custom else config["output_dir"]

    # 3) Selecionar tipos
    print()
    input("  Pressione Enter para selecionar os tipos de arquivo a recuperar...")
    selected_sigs = menu_selecionar_tipos()

    # 4) Confirmar e iniciar
    clear_screen()
    print_header()
    print("  RESUMO DA OPERACAO:")
    print(f"    Dispositivo  : {device_path}")
    print(f"    Pasta saida  : {output_dir}")
    print(f"    Tipos        : {', '.join(selected_sigs.keys())}")
    lim = config.get("limit_bytes")
    print(f"    Limite       : {format_bytes(lim) if lim else 'Disco inteiro'}")
    print()

    if not TQDM_AVAILABLE:
        print("  [!] tqdm nao instalado. Instale com: pip install tqdm")
        print("      A barra de progresso nao sera exibida.")
        print()

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


def menu_configuracoes(config):
    while True:
        clear_screen()
        print_header()
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
                config["limit_bytes"] = int(gb * 1024 ** 3) if gb > 0 else None
                print(f"  Limite definido: {format_bytes(config['limit_bytes']) if config['limit_bytes'] else 'Sem limite'}")
                input("  Pressione Enter para continuar.")
            except ValueError:
                print("  Valor invalido.")
                input("  Pressione Enter para continuar.")
        elif choice == "0":
            break


# =============================================================================
# PONTO DE ENTRADA
# =============================================================================

def main():
    config = {
        "output_dir": DEFAULT_OUTPUT_DIR,
        "limit_bytes": None,
    }

    clear_screen()
    print_header()

    if not TQDM_AVAILABLE:
        print("  [!] Dependencia 'tqdm' nao encontrada.")
        print("      Para barra de progresso, instale com:")
        print("        pip install tqdm")
        print()
        print("  A ferramenta funcionara normalmente, sem a barra de progresso.")
        print()
        input("  Pressione Enter para continuar...")

    print_admin_warning()
    if not is_admin():
        input("  Pressione Enter para continuar mesmo assim (alguns dispositivos podem falhar)...")

    try:
        menu_principal(config)
    except KeyboardInterrupt:
        print("\n\n  Encerrado pelo usuario.")
        sys.exit(0)


if __name__ == "__main__":
    main()
