
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
    is_compressed = str(filepath).endswith(".zst")
    if is_compressed:
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
    else:
        with filepath.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue


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
    by_base: dict[str, Path] = {}
    for p in base.iterdir():
        if not p.is_file() or p.suffix not in {".json", ".zst"}:
            continue
        key = _base_name(p)
        if key not in by_base or p.suffix == ".zst":
            by_base[key] = p
    return sorted(by_base.values())


def iter_yearly_files(sample_mode: bool, data_dir: Path = DATA_DIR, sample_dir: Path = SAMPLE_DATA_DIR) -> list[Path]:
    """Retourne la liste des fichiers dans les dossiers annuels (2022, 2023, __2024, 2025).
    Un seul fichier par jeu de données : si .json et .json.zst existent, on garde le .zst.
    """
    base = sample_dir if sample_mode else data_dir
    if not base.exists():
        return []
    
    # Dossiers à scanner
    yearly_dirs = ["2022", "2023", "__2024", "2025"]
    
    all_files = []
    by_base: dict[str, Path] = {}
    
    for year_dir in yearly_dirs:
        year_path = base / year_dir
        if not year_path.exists() or not year_path.is_dir():
            continue
        
        for p in year_path.iterdir():
            if not p.is_file() or p.suffix not in {".json", ".zst"}:
                continue
            key = f"{year_dir}/{_base_name(p)}"  # Inclure le dossier dans la clé
            if key not in by_base or p.suffix == ".zst":
                by_base[key] = p
    
    return sorted(by_base.values())
