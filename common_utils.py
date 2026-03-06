
import json
import subprocess
from pathlib import Path
from typing import Dict, Generator, Optional


# Constants relative to this file (assumed to be in the project root)
PROJECT_ROOT = Path(__file__).parent
DATA_DIR = PROJECT_ROOT
SAMPLE_DATA_DIR = PROJECT_ROOT / "sample_data"
UPTIMES_DIR_NAME = "uptimes"


def parse_jsonl_stream(filepath: Path) -> Generator[Dict, None, None]:
    """Lit un fichier JSONL ou .zst ligne par ligne, sans tout charger en mémoire."""
    proc = subprocess.Popen(
        ["zstdcat", str(filepath)],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
        bufsize=8192,
    )
    assert proc.stdout is not None
    for line in proc.stdout:
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue
    proc.wait()


def _base_name(path: Path) -> str:
    """Nom logique du fichier (sans .json ni .zst) pour dédupliquer .json / .json.zst."""
    name = path.name
    if name.endswith(".zst"):
        name = name[:-4]  # remove .zst
    if name.endswith(".json"):
        name = name[:-5]  # remove .json
    return name


def iter_uptime_files(sample_mode: bool, data_dir: Path = DATA_DIR, sample_dir: Path = SAMPLE_DATA_DIR) -> list[Path]:
    """Retourne la liste des fichiers uptimes à traiter (full ou sample).
    Un seul fichier par jeu de données : si .json et .json.zst existent, on garde le .zst.
    """
    base = (sample_dir / UPTIMES_DIR_NAME) if sample_mode else (data_dir / UPTIMES_DIR_NAME)
    if not base.exists():
        return []
        
    return sorted(
        p for p in base.iterdir()
        if p.is_file() and p.suffix == ".zst"
    )
