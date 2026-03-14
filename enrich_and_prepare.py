#!/usr/bin/env python3
"""
enrich_and_prepare.py
=====================
Pipeline en 3 étapes pour préparer les données de phishing pour HDBSCAN.

Étape 1 : Consolidation & enrichissement
  - Lit le JSONL principal (domaines malicieux avec takedown WHOIS).
  - Scanne un répertoire optionnel (--extra-dir) pour compléter les données
    manquantes via jointure sur le registered domain (rd).
  - Sauvegarde le résultat dans un nouveau JSONL enrichi.

Étape 2 : Feature engineering
  - Aplatit les structures imbriquées (uptime list).
  - Filtre les IPs CDN/Proxy connus (Cloudflare, AWS, Fastly…).
  - Calcule delta temporel discovery→création, clampé à 30j et normalisé.
  - Nettoie les URI paths (tokens dynamiques → <DYNAMIC_DIR>).
  - Applique TF-IDF (HashingVectorizer, stateless) sur URI path nettoyé.
  - Réduit la matrice TF-IDF via TruncatedSVD (n_components configurable).
  - Sauvegarde un CSV "flat" prêt à être consommé par run_hdbscan.py.

Usage:
  python enrich_and_prepare.py \\
    --input analysis_results/malicious_domains_takedown_whois_full_20260312_080250.jsonl \\
    [--extra-dir /ssd/cyber_cour/] \\
    [--output-enriched analysis_results/enriched.jsonl] \\
    [--output-features analysis_results/features_enriched.csv] \\
    [--uri-svd-components 10] \\
    [--batch-size 10000]
"""

import argparse
import gc
import ipaddress
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Generator, Iterator, List, Optional, Tuple
from urllib.parse import urlparse

import numpy as np
import pandas as pd
import scipy.sparse as sp
from sklearn.decomposition import TruncatedSVD
from sklearn.feature_extraction.text import HashingVectorizer

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# CDN/Proxy CIDR ranges to filter out of IP features
CDN_CIDRS = [
    # Cloudflare
    "104.21.0.0/16",
    "172.67.0.0/16",
    "108.162.0.0/16",
    "162.159.0.0/16",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "188.114.96.0/20",
    "190.93.240.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    # AWS CloudFront
    "13.32.0.0/15",
    "13.224.0.0/14",
    "13.35.0.0/16",
    "52.84.0.0/15",
    # Fastly
    "151.101.0.0/16",
    # Akamai (ranges les plus courants)
    "23.32.0.0/11",
    "184.24.0.0/13",
]

# Compiled CDN networks
CDN_NETWORKS = [ipaddress.ip_network(cidr, strict=False) for cidr in CDN_CIDRS]

# Regex: remplace segments dynamiques dans le path
# - Suites de chiffres >= 6 (timestamps Unix, IDs numériques)
# - Strings hexadécimales >= 8 chars
# - UUIDs
_RE_DYNAMIC = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"  # UUID
    r"|[0-9a-fA-F]{16,}"  # Long hex
    r"|\d{6,}"             # Long digits (timestamps etc.)
)

MAX_TEMPORAL_DAYS = 30      # Clamp temporel
REFERENCE_DATE = datetime(2020, 1, 1, tzinfo=timezone.utc)  # Pour fallback si pas de cd


# ---------------------------------------------------------------------------
# Utility: JSONL streaming
# ---------------------------------------------------------------------------

def _stream_jsonl(path: Path) -> Generator[Dict, None, None]:
    """Lit un fichier JSONL ou .zst ligne par ligne (streaming, low RAM)."""
    is_zst = str(path).endswith(".zst")
    if is_zst:
        proc = subprocess.Popen(
            ["zstdcat", str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            bufsize=65536,
        )
        assert proc.stdout
        try:
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
        finally:
            proc.terminate()
            proc.wait()
    else:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue


def _is_valid_data_file(p: Path) -> bool:
    return p.is_file() and p.suffix in {".json", ".zst", ".jsonl"} and p.stat().st_size > 0


# ---------------------------------------------------------------------------
# Étape 1 : Consolidation & enrichissement
# ---------------------------------------------------------------------------

import sqlite3
import tempfile

class ExtraDataIndex:
    """
    Gestionnaire d'index d'enrichissement utilisant SQLite au lieu de la RAM.
    Permet de scanner 100GB+ de données sans saturer la mémoire.
    """
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.execute("CREATE TABLE IF NOT EXISTS extra (rd TEXT PRIMARY KEY, data TEXT)")
        # Optimisations SQLite pour l'insertion massive
        self.conn.execute("PRAGMA journal_mode = OFF")
        self.conn.execute("PRAGMA synchronous = OFF")
        self.conn.execute("PRAGMA cache_size = -2000000") # 2GB de cache RAM pour SQLite

    def is_empty(self) -> bool:
        cursor = self.conn.execute("SELECT COUNT(*) FROM extra LIMIT 1")
        return cursor.fetchone()[0] == 0

    def build(self, extra_dir: Path):
        files = sorted([p for p in extra_dir.rglob("*") if _is_valid_data_file(p)])
        print(f"[Étape 1] Indexation de {len(files)} fichier(s) vers {self.db_path} ...")

        KEYS_TO_KEEP = {"rd", "fqdn", "url", "discovery_time", "dt", "metadata", "uptime"}
        total_scanned = 0
        batch = []
        
        for fpath in files:
            print(f"  → Scan: {fpath.name}")
            for rec in _stream_jsonl(fpath):
                total_scanned += 1
                rd = rec.get("rd") or rec.get("fqdn") or rec.get("domain")
                if not rd:
                    continue
                
                # Pruning minimal pour économiser de la place disque
                pruned = {k: v for k, v in rec.items() if k in KEYS_TO_KEEP and v}
                if not pruned:
                    continue
                
                batch.append((rd, json.dumps(pruned)))
                
                if len(batch) >= 20000:
                    self.conn.executemany("INSERT OR IGNORE INTO extra VALUES (?, ?)", batch)
                    self.conn.commit()
                    batch = []
                    print(f"    Records scannés : {total_scanned:,} ...", end="\r")
        
        if batch:
            self.conn.executemany("INSERT OR IGNORE INTO extra VALUES (?, ?)", batch)
            self.conn.commit()
        
        print("\n  → Création de l'index sur 'rd' (accélère la jointure)...")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_rd ON extra(rd)")
        print(f"  → Index prêt. Total scannés : {total_scanned:,}")

    def get(self, rd: str) -> Optional[Dict]:
        cursor = self.conn.execute("SELECT data FROM extra WHERE rd = ?", (rd,))
        row = cursor.fetchone()
        return json.loads(row[0]) if row else None

    def close(self):
        self.conn.close()


def enrich_record(rec: Dict, index: ExtraDataIndex) -> Dict:
    """
    Complète les champs manquants de rec avec les données de l'index SQLite.
    """
    rd = rec.get("rd") or rec.get("fqdn")
    if not rd:
        return rec

    extra = index.get(rd)
    if not extra:
        return rec

    enriched = dict(rec)
    for key, val in extra.items():
        if key not in enriched or enriched[key] is None:
            enriched[key] = val
        elif key == "uptime" and isinstance(val, list) and isinstance(enriched.get("uptime"), list):
            existing_dts = {e.get("dt") for e in enriched["uptime"] if isinstance(e, dict)}
            for entry in val:
                if isinstance(entry, dict) and entry.get("dt") not in existing_dts:
                    enriched["uptime"].append(entry)
    return enriched


def run_step1_enrichment(
    input_path: Path,
    output_enriched: Path,
    extra_dir: Optional[Path],
    db_dir: Optional[Path] = None,
) -> int:
    """
    Étape 1 : Lit le JSONL principal, enrichit via index SQLite, sauvegarde.
    """
    print(f"\n{'='*70}")
    print(f"ÉTAPE 1 — Consolidation & Enrichissement (Version SQLite Persistante)")
    print(f"  Source  : {input_path}")
    print(f"  Extra   : {extra_dir or '(aucun)'}")
    print(f"  Sortie  : {output_enriched}")
    print(f"{'='*70}")

    # On définit un chemin d'index stable sur le SSD
    if db_dir:
        db_path = db_dir / "phishing_enrichment_index.db"
    else:
        # Fallback par défaut sur /ssd si possible, sinon /tmp
        ssd_path = Path("/ssd/cyber/tmp_index")
        if ssd_path.parent.exists():
            ssd_path.mkdir(exist_ok=True)
            db_path = ssd_path / "phishing_enrichment_index.db"
        else:
            db_path = Path("/tmp/phishing_enrichment_index.db")

    index = ExtraDataIndex(db_path=db_path)
    try:
        if extra_dir and extra_dir.exists():
            if index.is_empty():
                index.build(extra_dir)
            else:
                print(f"[+] Index SQLite existant trouvé ({db_path}). Réutilisation sans rescan.")
        
        written = 0
        with output_enriched.open("w", encoding="utf-8") as out_f:
            for i, rec in enumerate(_stream_jsonl(input_path)):
                rec = enrich_record(rec, index)
                out_f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                written += 1
                if written % 50_000 == 0:
                    print(f"  Enrichissement : {written:,} records écrits...", end="\r")
        
        print(f"\n[+] Étape 1 terminée. {written:,} records → {output_enriched}")
        return written
    finally:
        index.close()


# ---------------------------------------------------------------------------
# Étape 2 : Feature extraction (flatten + feature engineering)
# ---------------------------------------------------------------------------

def _is_cdn_ip(ip_str: str) -> bool:
    """Retourne True si l'IP appartient à un réseau CDN/Proxy connu."""
    try:
        addr = ipaddress.ip_address(ip_str.strip())
        return any(addr in net for net in CDN_NETWORKS)
    except ValueError:
        return False


def _extract_clean_ips(uptime: list) -> List[str]:
    """
    Extrait les IPs des entrées DNS dans l'uptime.
    Filtre les IPs CDN/Proxy. Retourne une liste d'IPs uniques conservées.
    """
    ips = set()
    for entry in uptime:
        if not isinstance(entry, dict) or entry.get("type") != "dns":
            continue
        for ip in entry.get("arec") or []:
            if ip and not _is_cdn_ip(ip):
                ips.add(ip)
    return sorted(ips)


def _parse_datetime(dt_str: Optional[str]) -> Optional[datetime]:
    """Parse une date au format ISO 8601 ou YYYY-MM-DD. Retourne None si invalide."""
    if not dt_str:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(str(dt_str)[:19], fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _compute_temporal_feature(
    discovery_time: Optional[str],
    creation_date: Optional[str],
) -> float:
    """
    Calcule le delta (discovery_time - cd) en jours.
    - Clampé à [0, MAX_TEMPORAL_DAYS].
    - Normalisé entre 0 et 1 (divisé par MAX_TEMPORAL_DAYS).
    Retourne 0.5 (valeur neutre) si l'une des dates est manquante.
    """
    dt_disc = _parse_datetime(discovery_time)
    dt_cd = _parse_datetime(creation_date)

    if dt_disc is None or dt_cd is None:
        return 0.5  # valeur neutre pour les NaN

    delta_days = (dt_disc - dt_cd).days
    clamped = max(0, min(delta_days, MAX_TEMPORAL_DAYS))
    return clamped / MAX_TEMPORAL_DAYS


def _clean_uri_path(url: Optional[str]) -> str:
    """
    Extrait et nettoie le chemin (path) d'une URL.
    Remplace les segments dynamiques (timestamps, hex, UUIDs) par <DYNAMIC_DIR>.
    Retourne une chaîne de tokens séparés par des espaces.
    """
    if not url:
        return ""
    try:
        path = urlparse(url).path
    except Exception:
        return ""

    # Remplace les segments dynamiques
    path_clean = _RE_DYNAMIC.sub("<DYNAMIC_DIR>", path)
    # Remplace les / par des espaces et nettoie
    tokens = [t for t in path_clean.replace("/", " ").split() if t]
    return " ".join(tokens)


def _extract_whois_fields(uptime: list) -> Tuple[int, str, str]:
    """Extrait iana_id, creation_date, expiration_date depuis les entrées WHOIS."""
    iana_id = -1
    cd = ""
    ed = ""
    for entry in uptime:
        if not isinstance(entry, dict) or entry.get("type") != "whois":
            continue
        if iana_id == -1 and entry.get("iana_id"):
            try:
                iana_id = int(entry["iana_id"])
            except (ValueError, TypeError):
                pass
        if not cd and entry.get("cd"):
            cd = str(entry["cd"])
        if not ed and entry.get("ed"):
            ed = str(entry["ed"])
    return iana_id, cd, ed


def _extract_html_titles(uptime: list) -> str:
    """Collecte tous les html_title uniques depuis les entrées content."""
    titles = []
    seen = set()
    for entry in uptime:
        if not isinstance(entry, dict) or entry.get("type") != "content":
            continue
        title = entry.get("html_title")
        if title and str(title) not in seen:
            seen.add(str(title))
            titles.append(str(title))
    return " | ".join(titles)


def _compute_uptime_duration(uptime: list, cd: str) -> Optional[float]:
    """
    Durée de vie de l'attaque : delta entre première et dernière entrée uptime.
    Retourne des jours (float) ou None si non calculable.
    """
    dts = []
    for entry in uptime:
        if not isinstance(entry, dict):
            continue
        dt = _parse_datetime(entry.get("dt"))
        if dt:
            dts.append(dt)
    if len(dts) < 2:
        return None
    return (max(dts) - min(dts)).total_seconds() / 86400.0


def flatten_record(rec: Dict) -> Dict:
    """
    Aplatit un record JSONL en un dictionnaire de features scalaires.
    Robuste aux clés manquantes (retourne None/valeurs par défaut).
    """
    if not isinstance(rec, dict):
        return {}

    uptime = rec.get("uptime") or []
    metadata = rec.get("metadata") or {}
    takedown = rec.get("takedown") or {}

    # Identifiants
    rd = rec.get("rd") or rec.get("fqdn", "")
    fqdn = rec.get("fqdn", "")
    url = rec.get("url", "")
    discovery_time = rec.get("discovery_time") or rec.get("dt")

    # Metadata
    tld = metadata.get("tld", "")
    src = metadata.get("src", "")
    trg = metadata.get("trg", "")

    # Fallback TLD depuis le domaine
    if not tld and rd and "." in rd:
        tld = rd.rsplit(".", 1)[-1]

    # WHOIS
    iana_id, cd, ed = _extract_whois_fields(uptime)

    # Feature temporelle clampée et normalisée
    temporal_norm = _compute_temporal_feature(discovery_time, cd)

    # IPs filtrées (sans CDN)
    clean_ips = _extract_clean_ips(uptime)

    # HTML titles
    html_titles = _extract_html_titles(uptime)

    # URI path nettoyé
    uri_path_clean = _clean_uri_path(url)

    # Durée de vie de l'attaque
    uptime_dur_days = _compute_uptime_duration(uptime, cd)

    # Durée d'enregistrement (cd → ed)
    registration_dur = None
    if cd and ed:
        d_cd = _parse_datetime(cd)
        d_ed = _parse_datetime(ed)
        if d_cd and d_ed:
            registration_dur = max(0.0, (d_ed - d_cd).days)

    return {
        "rd": rd,
        "fqdn": fqdn,
        "url": url,
        "discovery_time": discovery_time,
        "tld": tld,
        "src": src,
        "trg": trg,
        "iana_id": iana_id,
        "creation_date": cd,
        "expiration_date": ed,
        "temporal_norm": temporal_norm,           # [0,1] clamped 30j
        "clean_ips": " ".join(clean_ips),         # IPs sans CDN
        "n_clean_ips": len(clean_ips),
        "html_titles": html_titles,
        "uri_path_clean": uri_path_clean,
        "uptime_dur_days": uptime_dur_days,
        "registration_dur_days": registration_dur,
        "n_uptime_entries": len(uptime),
    }


def run_step2_features(
    enriched_path: Path,
    output_features: Path,
    uri_svd_components: int = 10,
    batch_size: int = 10000,
) -> None:
    """
    Étape 2 : Lit le JSONL enrichi, aplatit, applique TF-IDF + SVD sur URI path,
    puis sauvegarde un CSV de features.
    """
    print(f"\n{'='*70}")
    print(f"ÉTAPE 2 — Feature Engineering")
    print(f"  Source  : {enriched_path}")
    print(f"  Sortie  : {output_features}")
    print(f"  URI SVD : {uri_svd_components} composantes")
    print(f"{'='*70}")

    # --- Passe 1 : aplatissement de tous les records ---
    print("[+] Passe 1 : Aplatissement des records...")
    rows = []
    for i, rec in enumerate(_stream_jsonl(enriched_path)):
        flat = flatten_record(rec)
        if flat:
            rows.append(flat)
        if (i + 1) % 100_000 == 0:
            print(f"  Traités : {i+1:,}", end="\r")

    print(f"\n[+] {len(rows):,} records aplatis.")
    df = pd.DataFrame(rows)

    # --- TF-IDF + SVD sur URI path ---
    print(f"[+] Vectorisation URI path (TF-IDF HashingVectorizer, ngram (1,2))...")
    uri_paths = df["uri_path_clean"].fillna("").tolist()

    # HashingVectorizer = stateless (pas besoin de fit sur tout le corpus)
    hv = HashingVectorizer(
        ngram_range=(1, 2),
        analyzer="word",
        norm="l2",
        n_features=2**14,  # 16384 features hashées
        alternate_sign=False,
    )
    X_uri = hv.transform(uri_paths)
    print(f"  Matrice TF-IDF URI shape: {X_uri.shape}")

    # TruncatedSVD pour réduire à uri_svd_components colonnes denses
    n_comp = min(uri_svd_components, X_uri.shape[0] - 1, X_uri.shape[1] - 1)
    print(f"[+] TruncatedSVD sur URI TF-IDF ({n_comp} composantes)...")
    svd = TruncatedSVD(n_components=n_comp, random_state=42)
    X_uri_dense = svd.fit_transform(X_uri)
    explained = svd.explained_variance_ratio_.sum()
    print(f"  Variance expliquée par SVD URI: {explained:.1%}")

    for i in range(n_comp):
        df[f"uri_svd_{i}"] = X_uri_dense[:, i]

    del X_uri, X_uri_dense
    gc.collect()

    # --- Normalisation uptime_dur_days ---
    if df["uptime_dur_days"].notna().any():
        max_dur = df["uptime_dur_days"].max()
        if max_dur and max_dur > 0:
            df["uptime_dur_norm"] = (df["uptime_dur_days"].fillna(0) / max_dur).clip(0, 1)
        else:
            df["uptime_dur_norm"] = 0.0
    else:
        df["uptime_dur_norm"] = 0.0

    # --- Normalisation registration_dur_days ---
    if df["registration_dur_days"].notna().any():
        max_reg = df["registration_dur_days"].max()
        if max_reg and max_reg > 0:
            df["registration_dur_norm"] = (df["registration_dur_days"].fillna(0) / max_reg).clip(0, 1)
        else:
            df["registration_dur_norm"] = 0.0
    else:
        df["registration_dur_norm"] = 0.0

    # --- Normalisation n_clean_ips ---
    max_ips = df["n_clean_ips"].max()
    if max_ips and max_ips > 0:
        df["n_clean_ips_norm"] = (df["n_clean_ips"] / max_ips).clip(0, 1)
    else:
        df["n_clean_ips_norm"] = 0.0

    print(f"[+] Sauvegarde du CSV de features → {output_features}")
    df.to_csv(output_features, index=False, compression=None)

    # Rapport
    print(f"\n{'='*70}")
    print(f"RAPPORT ÉTAPE 2")
    print(f"  Records        : {len(df):,}")
    print(f"  Colonnes totales: {len(df.columns)}")
    print(f"  temporal_norm  : mean={df['temporal_norm'].mean():.3f}, std={df['temporal_norm'].std():.3f}")
    print(f"  uptime_dur_norm: mean={df['uptime_dur_norm'].mean():.3f}")
    if "trg" in df.columns:
        print(f"  Brands uniques (trg): {df['trg'].nunique()}")
    if "iana_id" in df.columns:
        val = (df["iana_id"] != -1).mean()
        print(f"  Couverture iana_id : {val:.1%}")
    print(f"  IPs CDN filtrées : cf. colonne clean_ips (IPs proxy absentes)")
    print(f"{'='*70}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Pipeline d'enrichissement et feature engineering pour HDBSCAN phishing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--input", required=True,
        help="Fichier JSONL principal (domaines malicieux avec takedown WHOIS).",
    )
    parser.add_argument(
        "--extra-dir", default=None,
        help="Répertoire optionnel à scanner pour enrichir les données (jointure sur 'rd').",
    )
    parser.add_argument(
        "--output-enriched", default=None,
        help="Chemin du JSONL enrichi (défaut: même dossier que --input, suffix _enriched.jsonl).",
    )
    parser.add_argument(
        "--output-features", default=None,
        help="Chemin du CSV de features (défaut: même dossier que --input, suffix _features.csv).",
    )
    parser.add_argument(
        "--uri-svd-components", type=int, default=10,
        help="Nombre de composantes SVD pour la réduction URI path TF-IDF (défaut: 10).",
    )
    parser.add_argument(
        "--batch-size", type=int, default=10000,
        help="Taille de batch (réservé pour usage futur, défaut: 10000).",
    )
    parser.add_argument(
        "--skip-enrichment", action="store_true",
        help="Sauter l'étape 1 (utilise --output-enriched comme fichier déjà enrichi).",
    )

    parser.add_argument(
        "--db-dir", default=None,
        help="Répertoire pour l'index SQLite (recommandé sur /ssd). Si l'index existe déjà, le scan est sauté.",
    )

    args = parser.parse_args()

    input_path = Path(args.input).resolve()
    if not input_path.exists():
        print(f"[ERREUR] Fichier introuvable : {input_path}")
        return 1

    # Chemins de sortie par défaut
    base_name = input_path.stem
    if base_name.endswith(".jsonl"):
        base_name = base_name[:-6]  # enlève double extension

    out_dir = input_path.parent
    enriched_path = Path(args.output_enriched).resolve() if args.output_enriched else \
        out_dir / f"{base_name}_enriched.jsonl"
    features_path = Path(args.output_features).resolve() if args.output_features else \
        out_dir / f"{base_name}_features.csv"

    extra_dir = Path(args.extra_dir).resolve() if args.extra_dir else None
    db_dir = Path(args.db_dir).resolve() if args.db_dir else None

    # --- Étape 1 ---
    if not args.skip_enrichment:
        run_step1_enrichment(input_path, enriched_path, extra_dir, db_dir=db_dir)
    else:
        if not enriched_path.exists():
            print(f"[ERREUR] --skip-enrichment mais fichier enrichi introuvable : {enriched_path}")
            return 1
        print(f"[+] Étape 1 ignorée. Utilisation de : {enriched_path}")

    # --- Étape 2 ---
    run_step2_features(enriched_path, features_path, args.uri_svd_components, args.batch_size)

    print(f"\n[OK] Pipeline terminé.")
    print(f"  JSONL enrichi   : {enriched_path}")
    print(f"  Features CSV    : {features_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
