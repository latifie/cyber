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

from common_utils import iter_uptime_files, parse_jsonl_stream


DATA_DIR = Path(__file__).parent
OUTPUT_DIR = DATA_DIR / "analysis_results"
OUTPUT_DIR.mkdir(exist_ok=True)
SAMPLE_DATA_DIR = DATA_DIR / "sample_data"


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


def extract(sample_mode: bool, data_dir: Optional[Path] = None) -> None:
    """Extrait les domaines malicieux avec takedown WHOIS ; écrit un JSONL complet."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    mode = "sample" if sample_mode else "full"
    out_path = OUTPUT_DIR / f"malicious_domains_takedown_whois_{mode}_{ts}.jsonl"

    if data_dir:
        files = iter_uptime_files(sample_mode, data_dir=data_dir)
    else:
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
    parser.add_argument(
        "--data-dir",
        type=str,
        help="Chemin optionnel vers le dossier contenant le sous-dossier 'uptimes/'.",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)
    
    data_dir_path = Path(args.data_dir) if args.data_dir else None
    extract(sample_mode=args.sample, data_dir=data_dir_path)


if __name__ == "__main__":
    main()
