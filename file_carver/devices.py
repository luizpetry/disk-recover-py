"""
Enumeracao e gerenciamento de dispositivos de bloco (discos, pendrives, etc.).
Suporta Windows (letras de drive + PhysicalDrive) e Linux (/dev/sd*, /dev/nvme*, etc.).
"""

from __future__ import annotations

import ctypes
import os
from typing import Optional

from .utils import format_bytes, get_device_size, is_windows


class DeviceInfo:
    """Informacoes sobre um dispositivo de bloco detectado."""

    __slots__ = ("label", "path", "drive_type", "size")

    def __init__(self, label: str, path: str, drive_type: str, size: Optional[int]) -> None:
        self.label = label
        self.path = path
        self.drive_type = drive_type
        self.size = size

    def __repr__(self) -> str:
        return f"DeviceInfo({self.label!r}, {self.path!r})"


def _get_device_size_win32(device_path: str) -> Optional[int]:
    """Obtem o tamanho do dispositivo via IOCTL no Windows."""
    try:
        GENERIC_READ = 0x80000000
        FILE_SHARE_READ = 0x00000001
        FILE_SHARE_WRITE = 0x00000002
        OPEN_EXISTING = 3
        IOCTL_DISK_GET_DRIVE_GEOMETRY_EX = 0x000700A0

        handle = ctypes.windll.kernel32.CreateFileW(  # type: ignore[attr-defined]
            device_path,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            0,
            None,
        )
        if handle == ctypes.c_void_p(-1).value:
            return None

        class DISK_GEOMETRY(ctypes.Structure):  # type: ignore[misc]
            _fields_ = [
                ("Cylinders", ctypes.c_int64),
                ("MediaType", ctypes.c_uint),
                ("TracksPerCylinder", ctypes.c_ulong),
                ("SectorsPerTrack", ctypes.c_ulong),
                ("BytesPerSector", ctypes.c_ulong),
            ]

        class DISK_GEOMETRY_EX(ctypes.Structure):  # type: ignore[misc]
            _fields_ = [
                ("Geometry", DISK_GEOMETRY),
                ("DiskSize", ctypes.c_int64),
                ("Data", ctypes.c_byte * 1),
            ]

        geo = DISK_GEOMETRY_EX()
        bytes_returned = ctypes.c_ulong(0)
        result = ctypes.windll.kernel32.DeviceIoControl(  # type: ignore[attr-defined]
            handle,
            IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
            None,
            0,
            ctypes.byref(geo),
            ctypes.sizeof(geo),
            ctypes.byref(bytes_returned),
            None,
        )
        ctypes.windll.kernel32.CloseHandle(handle)  # type: ignore[attr-defined]
        if result:
            return geo.DiskSize
        return None
    except Exception:
        return None


def _get_device_size_posix(device_path: str) -> Optional[int]:
    """Obtem o tamanho do dispositivo via seek no final (Linux/macOS)."""
    try:
        with open(device_path, "rb") as f:
            f.seek(0, 2)
            return f.tell()
    except Exception:
        return None


def get_device_size(device_path: str) -> Optional[int]:
    """Tenta obter o tamanho total do dispositivo em bytes."""
    if is_windows():
        return _get_device_size_win32(device_path)
    return _get_device_size_posix(device_path)


def list_drives_windows() -> list[DeviceInfo]:
    """Lista drives logicos e discos fisicos no Windows."""
    drives: list[DeviceInfo] = []

    # Drives logicos (letras A-Z)
    drive_bits = ctypes.windll.kernel32.GetLogicalDrives()  # type: ignore[attr-defined]
    type_names = {2: "Removivel", 3: "Fixo", 4: "Rede", 5: "CD/DVD", 6: "RAM"}

    for i in range(26):
        if drive_bits & (1 << i):
            letter = chr(ord("A") + i)
            drive_path = f"{letter}:\\"
            raw_path = f"\\\\.\\{letter}:"

            drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive_path)  # type: ignore[attr-defined]
            type_str = type_names.get(drive_type, "Desconhecido")

            size = _get_device_size_win32(raw_path)
            size_str = format_bytes(size)

            drives.append(DeviceInfo(
                label=f"{letter}: ({type_str}) - {size_str}",
                path=raw_path,
                drive_type=type_str,
                size=size,
            ))

    # Discos fisicos — enumerar ate encontrar um que nao existe
    for i in range(100):  # Suporta ate PhysicalDrive99
        phys_path = f"\\\\.\\PhysicalDrive{i}"
        size = _get_device_size_win32(phys_path)
        if size is None:
            # Se os primeiros 10 existiram, continua tentando; depois para
            if i >= 10:
                break
            continue
        size_str = format_bytes(size)
        drives.append(DeviceInfo(
            label=f"PhysicalDrive{i} (Disco Fisico) - {size_str}",
            path=phys_path,
            drive_type="Fisico",
            size=size,
        ))

    return drives


def list_drives_linux() -> list[DeviceInfo]:
    """Lista dispositivos de bloco no Linux."""
    drives: list[DeviceInfo] = []
    dev_dir = "/dev"
    prefixes = ("sd", "hd", "nvme", "vd", "xvd", "mmcblk")

    try:
        for name in sorted(os.listdir(dev_dir)):
            if not name.startswith(prefixes):
                continue
            # Apenas dispositivos raiz (nao particoes como sda1, nvme0n1p1)
            if name.startswith("nvme"):
                # nvme0n1 = disco, nvme0n1p1 = particao
                if "p" in name.split("nvme")[-1]:
                    continue
            elif any(c.isdigit() for c in name):
                # sda = disco, sda1 = particao
                continue

            full_path = os.path.join(dev_dir, name)
            size = _get_device_size_posix(full_path)
            size_str = format_bytes(size)
            drives.append(DeviceInfo(
                label=f"{full_path} - {size_str}",
                path=full_path,
                drive_type="Bloco",
                size=size,
            ))
    except Exception as e:
        print(f"Erro ao listar dispositivos: {e}")

    return drives


def list_drives() -> list[DeviceInfo]:
    """Lista todos os dispositivos de bloco disponiveis na plataforma atual."""
    if is_windows():
        return list_drives_windows()
    return list_drives_linux()
