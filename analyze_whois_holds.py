#!/usr/bin/env python3
"""
Analyse WHOIS-only (streaming) pour repérer des indices de takedown côté registrar.

Ce script ne regarde QUE les entrées uptime de type "whois" dans les exports uptimes.

Il produit:
  - Un comptage des whois_status observés.
  - Le nombre de domaines ayant au moins une observation whois_status == "inactive".
  - Le nombre de domaines ayant au moins une transition (active -> inactive) sur la timeline WHOIS.
  - Un fichier JSONL listant les événements "inactive" (avec l'entrée WHOIS complète).

Modes:
  - Full:     /ssd/cyber/uptimes/*.json(.zst)
  - Sample:   /ssd/cyber/sample_data/uptimes/*.json(.zst) via --sample
"""

import argparse
import json
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Generator, Iterable, Optional


DATA_DIR = Path(__file__).parent
OUTPUT_DIR = DATA_DIR / "analysis_results"
OUTPUT_DIR.mkdir(exist_ok=True)
SAMPLE_DATA_DIR = DATA_DIR / "sample_data"


def parse_jsonl_stream(filepath: Path) -> Generator[Dict, None, None]:
    """Lit un fichier JSONL (ou .zst) ligne par ligne, sans charger en mémoire."""
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


def iter_uptime_files(sample_mode: bool) -> list[Path]:
    base = (SAMPLE_DATA_DIR / "uptimes") if sample_mode else (DATA_DIR / "uptimes")
    if not base.exists():
        return []
    return sorted([p for p in base.iterdir() if p.is_file() and p.suffix in {".json", ".zst"}])


def norm_status(status: Optional[str]) -> Optional[str]:
    if not isinstance(status, str):
        return None
    s = status.strip().lower()
    return s if s else None


def analyze(sample_mode: bool) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    mode = "sample" if sample_mode else "full"
    out_path = OUTPUT_DIR / f"whois_inactive_events_{mode}_{ts}.jsonl"

    files = iter_uptime_files(sample_mode)
    if not files:
        print(f"[!] Aucun fichier uptimes trouvé en mode {mode}.")
        return

    total_records = 0
    total_whois_entries = 0
    status_counts: Counter[str] = Counter()
    inactive_events = 0
    domains_with_inactive = set()
    domains_with_active_to_inactive = set()

    with out_path.open("w", encoding="utf-8") as out_f:
        for fp in files:
            print(f"[+] Traitement: {fp}")
            for rec in parse_jsonl_stream(fp):
                total_records += 1

                uptime = rec.get("uptime") or []
                whois_entries = [e for e in uptime if isinstance(e, dict) and e.get("type") == "whois"]
                if not whois_entries:
                    continue

                whois_entries.sort(key=lambda e: e.get("dt") or "")
                rd = rec.get("rd") or rec.get("fqdn") or ""

                timeline = []
                for e in whois_entries:
                    total_whois_entries += 1
                    st = norm_status(e.get("whois_status"))
                    if st:
                        status_counts[st] += 1
                        timeline.append(st)
                    if st == "inactive":
                        inactive_events += 1
                        domains_with_inactive.add(rd)
                        out_f.write(
                            json.dumps(
                                {
                                    "rd": rec.get("rd"),
                                    "fqdn": rec.get("fqdn"),
                                    "url": rec.get("url"),
                                    "metadata": rec.get("metadata", {}),
                                    "whois_entry": e,  # entrée WHOIS complète
                                    "source_file": str(fp),
                                },
                                ensure_ascii=False,
                            )
                            + "\n"
                        )

                # transition active -> inactive (adjacente dans la timeline WHOIS)
                for prev, cur in zip(timeline, timeline[1:]):
                    if prev == "active" and cur == "inactive":
                        domains_with_active_to_inactive.add(rd)
                        break

    print("======================================================================")
    print(f"Mode: {mode}")
    print(f"Export événements WHOIS inactive: {out_path}")
    print("----------------------------------------------------------------------")
    print(f"Records traités (lignes)                 : {total_records:,}")
    print(f"Entrées WHOIS analysées                  : {total_whois_entries:,}")
    print(f"Événements WHOIS inactive                : {inactive_events:,}")
    print(f"Domaines distincts avec inactive         : {len(domains_with_inactive):,}")
    print(f"Domaines avec transition active->inactive: {len(domains_with_active_to_inactive):,}")
    print("----------------------------------------------------------------------")
    print("Top whois_status (normalisés):")
    for st, cnt in status_counts.most_common(20):
        print(f"  - {st}: {cnt:,}")
    print("======================================================================")


def main(argv: Optional[Iterable[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="Analyse WHOIS-only en streaming (active/inactive).")
    parser.add_argument("--sample", action="store_true", help="Utilise sample_data/uptimes/.")
    args = parser.parse_args(list(argv) if argv is not None else None)
    analyze(sample_mode=args.sample)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Analyse minimale des statuts WHOIS indiquant un blocage/suspension (piste \"registrar down\").

But:
  - Parcourir les exports \"uptimes\" en streaming (JSONL ou .zst) avec faible mémoire.
  - Extraire les entrées uptime de type \"whois\".
  - Compter les statuts WHOIS observés et, en particulier, les transitions active -> inactive.
  - Exporter les domaines ayant au moins une observation \"inactive\" dans un fichier séparé.

Mode:
  - Full: lit /ssd/cyber/uptimes/*.json(.zst)
  - Sample (--sample): lit /ssd/cyber/sample_data/uptimes/*.json(.zst)

Sorties (dans analysis_results/):
  - whois_inactive_domains_{full|sample}_YYYYMMDD_HHMMSS.jsonl
    (une ligne par événement WHOIS \"inactive\", avec le record minimal + l'entrée WHOIS complète)
"""

import argparse
import json
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Generator, Iterable, Optional


DATA_DIR = Path(__file__).parent
OUTPUT_DIR = DATA_DIR / "analysis_results"
OUTPUT_DIR.mkdir(exist_ok=True)

SAMPLE_DATA_DIR = DATA_DIR / "sample_data"


def parse_jsonl_stream(filepath: Path) -> Generator[Dict, None, None]:
    """Lit un fichier (JSONL ou JSONL compressé .zst) ligne par ligne."""
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


def iter_uptime_files(sample_mode: bool) -> Iterable[Path]:
    base = (SAMPLE_DATA_DIR / "uptimes") if sample_mode else (DATA_DIR / "uptimes")
    if not base.exists():
        return []
    return sorted([p for p in base.iterdir() if p.is_file() and p.suffix in {".json", ".zst"}])


def normalize_status(status: str) -> str:
    return status.strip().lower()


def analyze(sample_mode: bool) -> None:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    mode = "sample" if sample_mode else "full"

    out_path = OUTPUT_DIR / f"whois_inactive_domains_{mode}_{timestamp}.jsonl"

    files = list(iter_uptime_files(sample_mode))
    if not files:
        print(f"[!] Aucun fichier uptimes trouvé en mode {mode}.")
        return

    total_records = 0
    total_whois_entries = 0
    whois_status_counts: Counter[str] = Counter()
    inactive_events = 0
    domains_with_inactive = set()

    with out_path.open("w", encoding="utf-8") as out_f:
        for fp in files:
            print(f"[+] Traitement: {fp}")
            for rec in parse_jsonl_stream(fp):
                total_records += 1
                uptime = rec.get("uptime") or []
                rd = rec.get("rd") or rec.get("fqdn") or ""

                for e in uptime:
                    if not isinstance(e, dict) or e.get("type") != "whois":
                        continue
                    total_whois_entries += 1
                    st = e.get("whois_status")
                    if isinstance(st, str) and st:
                        whois_status_counts[normalize_status(st)] += 1

                    if isinstance(st, str) and normalize_status(st) == "inactive":
                        inactive_events += 1
                        domains_with_inactive.add(rd)
                        out_f.write(
                            json.dumps(
                                {
                                    "rd": rec.get("rd"),
                                    "fqdn": rec.get("fqdn"),
                                    "url": rec.get("url"),
                                    "metadata": rec.get("metadata", {}),
                                    "whois_entry": e,  # entrée WHOIS complète
                                    "source_file": str(fp),
                                },
                                ensure_ascii=False,
                            )
                            + "\n"
                        )

    print("======================================================================")
    print(f"Mode: {mode}")
    print(f"Fichier export (inactive): {out_path}")
    print("----------------------------------------------------------------------")
    print(f"Records traités (lignes)            : {total_records:,}")
    print(f\"Entrées WHOIS analysées             : {total_whois_entries:,}\")
    print(f\"Événements WHOIS inactive           : {inactive_events:,}\")
    print(f\"Domaines distincts avec inactive    : {len(domains_with_inactive):,}\")
    print(\"----------------------------------------------------------------------\")
    print(\"Top statuts WHOIS (normalisés):\")\n+    for st, cnt in whois_status_counts.most_common(20):\n+        print(f\"  - {st}: {cnt:,}\")\n+    print(\"======================================================================\")\n+\n+\n+def main(argv: Optional[Iterable[str]] = None) -> None:\n+    parser = argparse.ArgumentParser(description=\"Analyse WHOIS-only (active/inactive) en streaming\")\n+    parser.add_argument(\"--sample\", action=\"store_true\", help=\"Utilise sample_data/uptimes/\")\n+    args = parser.parse_args(list(argv) if argv is not None else None)\n+    analyze(sample_mode=args.sample)\n+\n+\n+if __name__ == \"__main__\":\n+    main()\n+\n*** End Patch"}failed to parse patch string: Expected ',' delimiter: line 1 column 34 (char 33)"}"}]}Oops tool call is malformed due to JSON wrapper. Need proper apply_patch freeform string. We'll call apply_patch correctly. Let's do. We'll also fix erroneous plus signs in file due to patch mistakes. We'll craft correctly. We'll add file with correct content no patch markers errors. We'll ensure no stray '+' inside. Let's reapply with correct. We'll mention timezone fix. We'll just implement minimal script; okay. We'll not mention hold; focus on inactive. Let's do. We'll call functions.apply_patch with Freeform. We'll be careful with patch grammar. Let's execute. We'll have to not run in parallel. We'll do tool call. We'll fix after. We'll also restore that in previous patch, there were stray `+` in strings; avoid. We'll rewrite file clean. Let's proceed. We'll do apply_patch with Add file full content. We'll include docstring, parse functions, counters, output. Ok. We'll create file. We'll use `datetime.now(timezone.utc)` for timestamp. We'll output status counts and transitions? It's fine. We'll include identify transitions active->inactive perhaps; but user currently wants push sample not gigas; this script fits. We'll include detect transitions maybe in output; but minimal. We'll keep only count inactive. We'll not be too long. Let's patch. We'll proceed. But note: apply_patch tool expects content lines preceded with +; ok.
#!/usr/bin/env python3
"""
Analyse minimale des statuts WHOIS "hold" (client/server) en streaming.

Objectif:
  - Parcourir les fichiers uptimes en streaming (bonne gestion mémoire).
  - Compter les entrées WHOIS dont le statut indique un "hold" (client hold, server hold, etc.).
  - Extraire les domaines concernés dans un fichier séparé.

Options:
  - Sans option: analyse complète sur les fichiers uptimes complets.
  - --sample  : analyse uniquement sur les fichiers dans sample_data/uptimes/.

Les fichiers générés incluent:
  - Un timestamp (YYYYMMDD_HHMMSS).
  - Le type de données: "full" ou "sample".
"""

import argparse
import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, Generator, Iterable, Optional


DATA_DIR = Path(__file__).parent
OUTPUT_DIR = DATA_DIR / "analysis_results"
OUTPUT_DIR.mkdir(exist_ok=True)

SAMPLE_DATA_DIR = DATA_DIR / "sample_data"


def parse_jsonl_stream(filepath: Path) -> Generator[Dict, None, None]:
    """
    Lit un fichier JSONL (ou JSON compressé .zst) ligne par ligne.
    Ne charge jamais tout le fichier en mémoire.
    """
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


def iter_uptime_files(sample_mode: bool) -> Iterable[Path]:
    """
    Retourne la liste des fichiers uptimes à analyser (full ou sample).
    """
    if sample_mode:
        base = SAMPLE_DATA_DIR / "uptimes"
    else:
        base = DATA_DIR / "uptimes"

    if not base.exists():
        return []

    # On prend tous les .json et .json.zst dans ce répertoire (pas de récursif, simple et explicite)
    files = sorted(
        [p for p in base.iterdir() if p.is_file() and (p.suffix in {".json", ".zst"})]
    )
    return files


def is_whois_hold(entry: Dict) -> bool:
    """
    Retourne True si l'entrée WHOIS contient un statut client/server hold.

    On regarde le champ 'whois_status' s'il existe, en mode case-insensitive,
    et on cherche 'client hold' ou 'server hold' (ou variantes collées).
    """
    if entry.get("type") != "whois":
        return False

    status = entry.get("whois_status")
    if not status or not isinstance(status, str):
        return False

    s = status.lower().replace("_", "").replace("-", "").replace(" ", "")
    # Exemples possibles: clienthold, client_hold, client hold, serverhold, server_hold, etc.
    return "clienthold" in s or "serverhold" in s


def analyze_whois_holds(sample_mode: bool = False) -> None:
    """
    Analyse les uptimes WHOIS pour trouver les statuts client/server hold.
    Écrit:
      - un résumé dans la sortie standard,
      - un fichier JSONL avec les domaines concernés.
    """
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    mode_label = "sample" if sample_mode else "full"

    # Fichier de sortie avec timestamp et type de données
    holds_output_path = (
        OUTPUT_DIR / f"whois_holds_{mode_label}_{timestamp}.jsonl"
    )

    total_records = 0
    total_whois_entries = 0
    total_whois_holds = 0
    domains_with_hold = set()

    uptime_files = list(iter_uptime_files(sample_mode))

    if not uptime_files:
        print(f"[!] Aucun fichier uptimes trouvé pour le mode '{mode_label}'.")
        return

    with holds_output_path.open("w", encoding="utf-8") as out_f:
        for filepath in uptime_files:
            print(f"[+] Traitement de {filepath} ...")
            for record in parse_jsonl_stream(filepath):
                total_records += 1

                rd = record.get("rd") or record.get("fqdn") or ""
                url = record.get("url", "")
                uptime = record.get("uptime") or []

                # Parcourir les entrées uptime de type WHOIS
                for entry in uptime:
                    if not isinstance(entry, dict):
                        continue

                    if entry.get("type") != "whois":
                        continue

                    total_whois_entries += 1

                    if is_whois_hold(entry):
                        total_whois_holds += 1
                        domains_with_hold.add(rd)

                        out_record = {
                            "rd": rd,
                            "fqdn": record.get("fqdn"),
                            "url": url,
                            "whois_entry": entry,
                            "metadata": record.get("metadata", {}),
                        }
                        out_f.write(json.dumps(out_record, ensure_ascii=False) + "\n")

    print("======================================================================")
    print(f"Mode de données : {mode_label}")
    print(f"Fichier de sortie des domaines en hold : {holds_output_path}")
    print("----------------------------------------------------------------------")
    print(f"Enregistrements (lignes) traités        : {total_records:,}")
    print(f"Entrées WHOIS analysées                 : {total_whois_entries:,}")
    print(f"Entrées WHOIS avec client/server hold   : {total_whois_holds:,}")
    print(f"Domaines distincts avec client/server hold : {len(domains_with_hold):,}")
    print("======================================================================")


def main(argv: Optional[Iterable[str]] = None) -> None:
    parser = argparse.ArgumentParser(
        description="Analyse minimale des statuts WHOIS client/server hold."
    )
    parser.add_argument(
        "--sample",
        action="store_true",
        help="Utilise les données d'échantillon dans sample_data/uptimes/ au lieu des données complètes.",
    )

    args = parser.parse_args(list(argv) if argv is not None else None)
    analyze_whois_holds(sample_mode=args.sample)


if __name__ == "__main__":
    main()

