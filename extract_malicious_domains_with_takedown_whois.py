#!/usr/bin/env python3
"""
Extrait les domaines malicieux (et toutes leurs infos) à partir du champ "takedown"
dans les données uptimes, en ne gardant que les enregistrements où le takedown
concerne le WHOIS (takedown_reason == "whois" ou au moins un élément dans
takedowns avec type == "whois").

Source : uptimes (JSONL ou .zst).
  - Sans option : données complètes (uptimes/).
  - --sample    : échantillon (sample_data/uptimes/).

Sortie : analysis_results/malicious_domains_takedown_whois_{full|sample}_{timestamp}.jsonl
  Une ligne par domaine malicieux avec takedown WHOIS ; contenu = enregistrement complet.
"""

import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Generator, Iterable, Optional


DATA_DIR = Path(__file__).parent
OUTPUT_DIR = DATA_DIR / "analysis_results"
OUTPUT_DIR.mkdir(exist_ok=True)
SAMPLE_DATA_DIR = DATA_DIR / "sample_data"


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


def iter_uptime_files(sample_mode: bool) -> list[Path]:
    """Retourne la liste des fichiers uptimes à traiter (full ou sample).
    Un seul fichier par jeu de données : si .json et .json.zst existent, on garde le .zst.
    """
    base = (SAMPLE_DATA_DIR / "uptimes") if sample_mode else (DATA_DIR / "uptimes")
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


def takedown_has_whois(takedown: Optional[Dict]) -> bool:
    """True si le champ takedown indique un takedown WHOIS (clé whois / reason / type)."""
    if not takedown or not isinstance(takedown, dict):
        return False
    if takedown.get("takedown_reason") == "whois":
        return True
    for t in takedown.get("takedowns") or []:
        if isinstance(t, dict) and t.get("type") == "whois":
            return True
    return False


def extract(sample_mode: bool) -> None:
    """Extrait les domaines malicieux avec takedown WHOIS ; écrit un JSONL complet."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    mode = "sample" if sample_mode else "full"
    out_path = OUTPUT_DIR / f"malicious_domains_takedown_whois_{mode}_{ts}.jsonl"

    files = iter_uptime_files(sample_mode)
    if not files:
        print(f"[!] Aucun fichier uptimes trouvé en mode '{mode}'.")
        return

    total = 0
    written = 0

    with out_path.open("w", encoding="utf-8") as out_f:
        for fp in files:
            print(f"[+] Traitement: {fp}")
            for rec in parse_jsonl_stream(fp):
                total += 1
                takedown = rec.get("takedown")
                if not takedown_has_whois(takedown):
                    continue
                written += 1
                out_f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    print("======================================================================")
    print(f"Mode: {mode}")
    print(f"Fichier: {out_path}")
    print("----------------------------------------------------------------------")
    print(f"Enregistrements uptime lus   : {total:,}")
    print(f"Domaines malicieux (takedown whois) : {written:,}")
    print("======================================================================")


def main(argv: Optional[Iterable[str]] = None) -> None:
    parser = argparse.ArgumentParser(
        description="Extrait les domaines malicieux avec takedown WHOIS depuis les uptimes."
    )
    parser.add_argument(
        "--sample",
        action="store_true",
        help="Utilise sample_data/uptimes/ au lieu de uptimes/.",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)
    extract(sample_mode=args.sample)


if __name__ == "__main__":
    main()
