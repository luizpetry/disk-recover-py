# Disk Recover PY

File Carving Recovery Tool — recupera arquivos de discos/pendrives formatados buscando por magic bytes nos setores brutos.

## Funcionalidades

- **22 tipos de arquivo** suportados: JPEG, PNG, PDF, GIF, BMP, ZIP, MP3, MP4, AVI, WAV, EXE, TIFF, PSD, RAR, SQLite, XML, OGG, FLAC
- **Deduplicacao automatica** via hash MD5 — nao salva o mesmo arquivo duas vezes
- **Validacao de integridade** — verifica assinaturas antes de salvar
- **Reducao de falsos positivos** — validacao adicional para MP4/ISO Base Media
- **Cross-platform** — Windows e Linux
- **Modo interativo** e **modo batch** (argparse)
- **Barra de progresso** com tqdm (opcional)
- **Log detalhado** de todos os arquivos recuperados

## Instalacao

```bash
git clone https://github.com/luizpetry/disk-recover-py.git
cd disk-recover-py
pip install -r requirements.txt
```

Ou via pip:

```bash
pip install .
```

## Uso

### Modo interativo

```bash
python -m file_carver
```

### Modo batch

```bash
# Recuperar todos os tipos de um dispositivo
python -m file_carver --device "\\\\.\\D:" --output ./recuperados

# Recuperar apenas JPEG e PNG
python -m file_carver --device "\\\\.\\D:" --types JPEG,PNG

# Com limite de 1GB
python -m file_carver --device "\\\\.\\D:" --limit 1G

# Listar dispositivos disponiveis
python -m file_carver --list-devices

# Listar tipos suportados
python -m file_carver --list-types
```

### Como biblioteca

```python
from file_carver import scan_device, list_drives

# Listar dispositivos
drives = list_drives()
for d in drives:
    print(d.label, d.path)

# Escanear um dispositivo
results = scan_device(
    device_path="\\\\.\\D:",
    output_dir="./recuperados",
    limit_bytes=1024 * 1024 * 1024,  # 1 GB
)
print(results)
```

## Requisitos

- Python >= 3.9
- Executar como **Administrador** (Windows) ou **root** (Linux) para acesso raw ao disco
- `tqdm` (opcional, para barra de progresso)

## Tipos de Arquivo Suportados

| Tipo | Extensao | Tamanho Maximo | Footer |
|------|----------|---------------|--------|
| JPEG | .jpg | 15 MB | FF D9 |
| PNG | .png | 20 MB | IEND chunk |
| PDF | .pdf | 50 MB | %%EOF |
| GIF87 | .gif | 10 MB | 00 3B |
| GIF89 | .gif | 10 MB | 00 3B |
| BMP | .bmp | 30 MB | (tamanho no header) |
| ZIP | .zip | 200 MB | PK end of central dir |
| MP3 | .mp3 | 20 MB | — |
| MP4 | .mp4 | 2 GB | — |
| AVI | .avi | 2 GB | — |
| WAV | .wav | 300 MB | — |
| EXE | .exe | 100 MB | — |
| TIFF | .tif | 100 MB | — |
| PSD | .psd | 500 MB | — |
| RAR | .rar | 500 MB | RAR4: footer especial |
| SQLite | .db | 500 MB | — |
| XML | .xml | 50 MB | — |
| OGG | .ogg | 100 MB | — |
| FLAC | .flac | 300 MB | — |

## Estrutura do Projeto

```
disk-recover-py/
├── file_carver/
│   ├── __init__.py      # Exports publicos
│   ├── __main__.py      # Ponto de entrada (python -m file_carver)
│   ├── signatures.py    # Base de dados de magic bytes
│   ├── utils.py         # Funcoes utilitarias
│   ├── devices.py       # Enumeracao de dispositivos
│   ├── carver.py        # Engine de file carving
│   └── cli.py           # CLI interativo + argparse
├── recover.py           # Script original (legado)
├── requirements.txt
├── pyproject.toml
└── README.md
```

## Licenca

MIT
