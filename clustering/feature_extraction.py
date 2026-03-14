"""
feature_extraction.py — version enrichie
=========================================
Extraction de features depuis un enregistrement d'uptime de domaine malicieux.

Nouveautés v2 :
  - Filtrage des IPs CDN/Proxy (Cloudflare, AWS, Fastly…)
  - Feature temporelle : delta discovery_time→cd, clampée 30j, normalisée [0,1]
  - Extraction html_title depuis les entrées content
  - Nettoyage URI path (tokens dynamiques → <DYNAMIC_DIR>) ajouté à text_features
  - uptime_dur_days : durée de vie mesurée de l'attaque (jours)
"""

import ipaddress
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# CDN / Proxy CIDR ranges — IPs à ignorer pour le clustering infra
# ---------------------------------------------------------------------------
_CDN_CIDRS = [
    # Cloudflare
    "104.21.0.0/16", "172.67.0.0/16", "108.162.0.0/16", "162.159.0.0/16",
    "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "188.114.96.0/20", "190.93.240.0/20",
    "197.234.240.0/22", "198.41.128.0/17",
    # AWS CloudFront
    "13.32.0.0/15", "13.224.0.0/14", "13.35.0.0/16", "52.84.0.0/15",
    # Fastly
    "151.101.0.0/16",
    # Akamai (ranges courants)
    "23.32.0.0/11", "184.24.0.0/13",
]
_CDN_NETWORKS = [ipaddress.ip_network(c, strict=False) for c in _CDN_CIDRS]

# Segments dynamiques dans les URL paths (timestamps, UUIDs, hex longs, IDs)
_RE_DYNAMIC = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    r"|[0-9a-fA-F]{16,}"
    r"|\d{6,}"
)

MAX_TEMPORAL_DAYS = 30  # Clamp pour la feature temporelle


# ---------------------------------------------------------------------------
# Utilitaires internes
# ---------------------------------------------------------------------------

def _is_cdn_ip(ip_str: str) -> bool:
    """Retourne True si l'IP appartient à un réseau CDN/Proxy connu."""
    try:
        addr = ipaddress.ip_address(ip_str.strip())
        return any(addr in net for net in _CDN_NETWORKS)
    except ValueError:
        return False


def _parse_dt(dt_str: Optional[str]) -> Optional[datetime]:
    """Parse ISO 8601 ou YYYY-MM-DD. Retourne None si invalide."""
    if not dt_str:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
        try:
            return datetime.strptime(str(dt_str)[:19], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _clean_uri_path(url: Optional[str]) -> str:
    """
    Extrait le path d'une URL et remplace les segments dynamiques
    (timestamps, hex, UUIDs) par le token <DYNAMIC_DIR>.
    Retourne une chaîne de tokens séparés par des espaces.
    """
    if not url:
        return ""
    try:
        path = urlparse(url).path
    except Exception:
        return ""
    cleaned = _RE_DYNAMIC.sub("<DYNAMIC_DIR>", path)
    tokens = [t for t in cleaned.replace("/", " ").split() if t]
    return " ".join(tokens)


# ---------------------------------------------------------------------------
# Extraction principale
# ---------------------------------------------------------------------------

def extract_features(record: dict) -> dict:
    """
    Extrait les features d'un enregistrement uptime pour le clustering HDBSCAN.

    Structure attendue (clés importantes) :
    {
        "rd": "example.com",
        "fqdn": "www.example.com",
        "url": "http://example.com/path/to/phish",
        "discovery_time": "2022-12-23T16:30:10",
        "metadata": {"src": "APWG", "trg": "BancoEstado", "tld": "com"},
        "uptime": [
            {"type": "whois", "iana_id": 433, "cd": "2022-12-12", "ed": "2023-12-12"},
            {"type": "dns",   "arec": ["51.255.26.63"]},
            {"type": "content", "html_title": "Login - Bank", "dt": "..."},
        ]
    }

    Retourne un dict avec les colonnes attendues par DomainVectorizer.
    """
    if not isinstance(record, dict):
        return {}

    # --- Identifiants ---
    domain_id = record.get("rd") or record.get("fqdn") or record.get("id", "unknown")
    url = record.get("url", "")
    discovery_time = record.get("discovery_time") or record.get("dt")

    # --- Metadata ---
    metadata = record.get("metadata") or {}
    tld = metadata.get("tld", "")
    src = metadata.get("src", "")
    trg = metadata.get("trg", "")

    if not tld and domain_id and "." in domain_id:
        tld = domain_id.rsplit(".", 1)[-1]

    # --- Uptime : parsing des entrées typées ---
    uptime = record.get("uptime") or []
    iana_id = -1
    creation_ts = ""
    expiration_ts = ""
    ips_raw: set = set()
    html_titles: list = []
    uptime_dts: list = []

    for entry in uptime:
        if not isinstance(entry, dict):
            continue

        etype = entry.get("type")

        # Timestamp de l'entrée (pour durée de vie)
        entry_dt = _parse_dt(entry.get("dt"))
        if entry_dt:
            uptime_dts.append(entry_dt)

        if etype == "whois":
            if iana_id == -1 and entry.get("iana_id"):
                try:
                    iana_id = int(entry["iana_id"])
                except (ValueError, TypeError):
                    pass
            if not creation_ts and entry.get("cd"):
                creation_ts = str(entry["cd"])
            if not expiration_ts and entry.get("ed"):
                expiration_ts = str(entry["ed"])

        elif etype == "dns":
            for ip in entry.get("arec") or []:
                if ip:
                    ips_raw.add(ip)

        elif etype == "content":
            title = entry.get("html_title")
            if title and str(title) not in html_titles:
                html_titles.append(str(title))

    # --- IPs filtrées (sans CDN/Proxy) ---
    clean_ips = [ip for ip in sorted(ips_raw) if not _is_cdn_ip(ip)]

    # --- Feature temporelle : delta discovery→cd, clampée 30j, normalisée ---
    dt_disc = _parse_dt(discovery_time)
    dt_cd = _parse_dt(creation_ts)
    if dt_disc and dt_cd:
        delta_days = (dt_disc - dt_cd).days
        temporal_norm = max(0, min(delta_days, MAX_TEMPORAL_DAYS)) / MAX_TEMPORAL_DAYS
    else:
        temporal_norm = 0.5  # valeur neutre si données manquantes

    # --- Durée de vie de l'attaque (jours entre première et dernière mesure) ---
    uptime_dur_days = None
    if len(uptime_dts) >= 2:
        uptime_dur_days = (max(uptime_dts) - min(uptime_dts)).total_seconds() / 86400.0

    # --- URI path nettoyé ---
    uri_path_clean = _clean_uri_path(url)

    # --- Text features (bag-of-tokens pour FeatureHasher) ---
    text_parts = []

    # Marque ciblée (signal fort)
    if trg:
        text_parts.append(f"trg_{trg}")
    if src:
        text_parts.append(f"src_{src}")

    # Domain n-grams (3-grams de caractères sur le label principal)
    domain_base = domain_id.split(".")[0] if "." in domain_id else domain_id
    if len(domain_base) >= 3:
        text_parts += [domain_base[i:i+3] for i in range(len(domain_base) - 2)]

    # IPs propres (sans CDN)
    for ip in clean_ips:
        text_parts.append(f"ip_{ip}")

    # html_title tokens (mots normalisés)
    for title in html_titles:
        for word in title.lower().split():
            if len(word) >= 3:
                text_parts.append(f"title_{word}")

    # URI path tokens (après nettoyage des segments dynamiques)
    for token in uri_path_clean.split():
        if token != "<DYNAMIC_DIR>" and len(token) >= 2:
            text_parts.append(f"path_{token.lower()}")

    return {
        "id": domain_id,
        "url": url,
        "tld": tld,
        "registrar_id": iana_id,
        "asn": -1,                              # non présent dans les données
        "creation_ts": creation_ts,
        "temporal_norm": temporal_norm,          # [0,1] clampé 30j
        "uptime_dur_days": uptime_dur_days,      # durée de l'attaque (jours, peut être None)
        "uri_path_clean": uri_path_clean,        # path nettoyé pour TF-IDF externe
        "clean_ips_str": " ".join(clean_ips),   # IPs sans CDN
        "html_titles_str": " | ".join(html_titles),
        "text_features": " ".join(text_parts),  # bag-of-tokens pour FeatureHasher
    }
