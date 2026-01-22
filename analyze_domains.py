#!/usr/bin/env python3
"""
================================================================================
SCRIPT D'ANALYSE DES DOMAINES MALVEILLANTS - PROJET CYBER
================================================================================

DESCRIPTION:
------------
Analyse complète du vieillissement des domaines malveillants et de leur 
utilisation par les attaquants. Traite les transitions DNS, les takedowns,
les délais entre création et utilisation, et génère des visualisations.

VERSION:
--------
Optimisée pour la mémoire : traitement ligne par ligne (streaming)
- Supporte les fichiers compressés .zst (via zstdcat)
- Traitement par batch avec libération mémoire périodique
- Génération de graphiques et rapports détaillés

FONCTIONNALITÉS PRINCIPALES:
-----------------------------
1. Analyse des transitions DNS (NOERROR → NXDOMAIN)
   - Détection des transitions permanentes vs temporaires
   - Export des domaines down dans down_domains.jsonl

2. Calcul des délais création → utilisation malveillante
   - Distribution des délais par année
   - Identification des domaines utilisés immédiatement

3. Analyse des takedowns
   - Durées avant takedown par raison (content, dns, whois)
   - Durée entre achat et takedown par période de 6 mois

4. Évolution temporelle
   - Comparaison par année (2022-2025)
   - Taux de transitions permanentes
   - Métriques agrégées

5. Génération de visualisations
   - Graphiques de distribution
   - Évolutions temporelles
   - Comparaisons par période

STRUCTURE DES DONNÉES SOURCES:
-------------------------------
Répertoire racine: /ssd/cyber/

Fichiers JSONL (années):
  - 2022/, 2023/, 2024/, 2025/ : fichiers .jsonl par mois (01.jsonl, 02.jsonl, ...)
  - __2023/, __2024/ : fichiers compressés .jsonl.zst
  Format: Une ligne JSON par domaine avec:
    - metadata: {discovery_time, src, trg, ...}
    - whois_bd: {cd: date_creation, ...}
    - takedown: {uptime_dur, takedown_reason, ...}
    - (optionnel) uptime: [array d'entrées DNS/WHOIS temporelles]

Fichiers Uptimes (transitions DNS temporelles):
  - uptimes/*.json.zst ou uptimes/*.json
  Format: Une ligne JSON par domaine avec:
    - rd, fqdn, url, sid, discovery_time
    - uptime: [array d'entrées avec type='dns' ou type='whois']
      Chaque entrée: {dt: date, type: 'dns'|'whois', dns_status: 'NOERROR'|'NXDOMAIN', ...}

OUTPUTS GÉNÉRÉS:
----------------
Répertoire: analysis_results/

Fichiers de données:
  - down_domains.jsonl : Liste complète des domaines avec transition NOERROR→NXDOMAIN
    (tous les domaines: permanents et temporaires)
    Format: JSONL avec pour chaque domaine:
      - rd, fqdn, url, sid, discovery_time
      - transition: {transition_date, previous_date, remains_nxdomain, ...}
      - whois_bd: {cd: date_creation, ...}
      - takedown: {...}
      - dns_context: {before: [...], after: [...]}
  
  - down_domains_malicious.jsonl : Liste filtrée des domaines malicieux
    (seulement les domaines avec remains_nxdomain = true, down par le registrar)
    Format: JSONL avec les mêmes champs que down_domains.jsonl, plus:
      - malicious: true
      - takedown_reason: 'registrar_takedown'

Graphiques (PNG, 300 DPI):
  Les noms de fichiers incluent un suffixe indiquant les options d'exécution:
  - _full : Analyse complète (toutes les données)
  - _sample : Mode échantillon (données d'échantillon)
  - _dns-only : Mode DNS-only (seulement transitions DNS)
  - _sample_dns-only : Mode échantillon + DNS-only
  
  Exemples:
  - creation_delays_full.png : Distribution délais création → utilisation (analyse complète)
  - creation_delays_sample.png : Même graphique mais en mode échantillon
  - temporal_evolution_dns-only.png : Évolution temporelle (mode DNS-only)
  - dns_transitions.png : Transitions DNS NOERROR → NXDOMAIN
  - takedown_durations.png : Durées avant takedown
  - year_comparison.png : Comparaison détaillée par année
  - takedown_duration_by_6months.png : Durée achat→takedown par période 6 mois

Rapports textuels:
  - analysis_report.txt : Rapport général d'analyse
  - takedown_duration_by_6months_summary.txt : Résumé par période 6 mois

UTILISATION:
------------
Mode normal:
  python3 analyze_domains.py

Mode échantillon (utilise sample_data/):
  python3 analyze_domains.py --sample

Mode DNS-only (seulement transitions DNS, ignore JSONL):
  python3 analyze_domains.py --dns-only

AUTEUR: Analyse automatique
DATE: 2025
================================================================================
"""

import json
import os
import gc
import subprocess
from datetime import datetime
from collections import defaultdict, Counter
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Iterator, Generator
import warnings
warnings.filterwarnings('ignore')

# Barre de progression
try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    # Fallback simple si tqdm n'est pas disponible
    def tqdm(iterable, *args, **kwargs):
        return iterable

# Import des librairies de visualisation seulement quand nécessaire
try:
    import matplotlib
    matplotlib.use('Agg')  # Backend non-interactif pour éviter les problèmes
    import matplotlib.pyplot as plt
    import pandas as pd
    import numpy as np
    HAS_PLOTTING = True
except ImportError:
    HAS_PLOTTING = False
    print("Warning: matplotlib/pandas/numpy non disponibles, les graphiques seront désactivés")

# Configuration
DATA_DIR = Path(__file__).parent
OUTPUT_DIR = DATA_DIR / "analysis_results"
OUTPUT_DIR.mkdir(exist_ok=True)

# Taille des chunks pour traitement par batch (optionnel)
CHUNK_SIZE = 1000

# Mode échantillon : utilise les fichiers dans sample_data/ au lieu des fichiers complets
SAMPLE_DATA_DIR = DATA_DIR / "sample_data"


class DomainAnalyzer:
    """Analyseur de domaines malveillants - Version optimisée mémoire"""
    
    def __init__(self, sample_mode: bool = False, dns_only: bool = False):
        """
        Args:
            sample_mode: Si True, utilise les échantillons de données dans sample_data/
            dns_only: Si True, traite seulement les fichiers uptimes pour les transitions DNS (ignore JSONL)
        """
        self.sample_mode = sample_mode
        self.dns_only = dns_only
        
        # Ne stocker QUE les statistiques agrégées, pas les données brutes
        self.stats = {
            'total_domains': 0,
            'by_year': defaultdict(int),
            'dns_transitions': [],  # Seulement les métadonnées essentielles
            'creation_to_usage_delays': [],  # Seulement les valeurs numériques
            'takedown_durations': [],  # Seulement les valeurs numériques
            'whois_changes': [],  # Seulement les métadonnées essentielles
            'nxdomain_permanent_count': 0,
            'takedown_reasons': Counter(),
            'sources': Counter(),
            'targets': Counter()
        }
        self._processed_files = set()  # Pour éviter les doublons
        
        # Fichier de sortie pour les domaines down (NOERROR → NXDOMAIN)
        self.down_domains_file = None
        self.down_domains_count = 0
    
    def _get_filename_suffix(self) -> str:
        """
        Génère un suffixe pour les noms de fichiers basé sur les options d'exécution.
        
        Returns:
            str: Suffixe comme "_sample", "_dns-only", "_sample_dns-only", ou "_full"
        """
        parts = []
        if self.sample_mode:
            parts.append("sample")
        if self.dns_only:
            parts.append("dns-only")
        
        if not parts:
            return "_full"
        return "_" + "_".join(parts)
    
    def parse_jsonl_stream(self, filepath: Path, show_progress: bool = False) -> Generator[Dict, None, None]:
        """
        Parse un fichier JSONL ligne par ligne (générateur - ne charge pas tout en mémoire)
        Supporte les fichiers .zst compressés en lecture directe
        
        Args:
            filepath: Chemin du fichier (.jsonl ou .jsonl.zst)
            show_progress: Afficher une barre de progression
        
        Yields:
            Dict: Un enregistrement JSON à la fois
        """
        # Vérifier si le fichier est compressé (.zst)
        is_compressed = str(filepath).endswith('.zst') or str(filepath).endswith('.jsonl.zst')
        
        try:
            # Estimer le nombre de lignes pour la barre de progression
            total_lines = None
            if show_progress and HAS_TQDM:
                try:
                    if is_compressed:
                        # Pour les fichiers compressés, utiliser zstdcat pour compter les lignes
                        count_proc = subprocess.Popen(['zstdcat', str(filepath)], 
                                              stdout=subprocess.PIPE, 
                                              stderr=subprocess.DEVNULL,
                                              text=True)
                        total_lines = sum(1 for _ in count_proc.stdout)
                        count_proc.wait()
                    else:
                        # Compter les lignes rapidement (approximation)
                        with open(filepath, 'rb') as f:
                            total_lines = sum(1 for _ in f)
                except:
                    pass
            
            # En mode échantillon, utiliser les fichiers d'échantillon
            if self.sample_mode:
                # Les fichiers d'échantillon sont déjà limités, pas besoin de limiter ici
                pass
            
            # Ouvrir le fichier (compressé ou non)
            proc = None
            if is_compressed:
                # Lire directement depuis le fichier compressé avec zstdcat
                proc = subprocess.Popen(['zstdcat', str(filepath)], 
                                      stdout=subprocess.PIPE, 
                                      stderr=subprocess.DEVNULL,
                                      text=True, encoding='utf-8', bufsize=8192)
                f = proc.stdout
            else:
                f = open(filepath, 'r', encoding='utf-8')
            
            try:
                iterator = enumerate(f, 1)
                if show_progress and HAS_TQDM and total_lines:
                    iterator = tqdm(iterator, total=total_lines, 
                                   desc=f"  {filepath.name[:40]}", 
                                   unit=" lignes", leave=False)
                
                count = 0
                for line_num, line in iterator:
                    # En mode échantillon, traiter toutes les lignes (fichiers déjà limités)
                    
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        count += 1
                        yield record
                    except json.JSONDecodeError as e:
                        if line_num % 10000 == 0:  # Log seulement périodiquement
                            if not show_progress:  # Ne pas spammer si on a déjà tqdm
                                print(f"  Warning: Erreur ligne {line_num} dans {filepath.name}: {e}")
                        continue
            finally:
                if is_compressed and proc:
                    proc.terminate()
                    proc.wait()
                elif f and not is_compressed:
                    f.close()
        except FileNotFoundError:
            if is_compressed:
                print(f"Erreur: zstdcat non trouvé. Installez zstd pour lire les fichiers compressés.")
            raise
        except Exception as e:
            print(f"Erreur lecture {filepath}: {e}")
    
    def parse_uptime_stream(self, filepath: Path) -> Generator[Dict, None, None]:
        """
        Parse un fichier uptime JSON (générateur - ne charge jamais tout en mémoire)
        Supporte les fichiers .zst compressés en lecture directe
        
        Note: Les fichiers uptimes peuvent être volumineux (plusieurs GB), 
        on les traite TOUJOURS en streaming ligne par ligne (JSONL)
        """
        try:
            # Les fichiers uptimes sont en format JSONL (une ligne = un objet)
            # Utiliser parse_jsonl_stream qui gère déjà les fichiers compressés
            # et le streaming ligne par ligne de manière sûre
            yield from self.parse_jsonl_stream(filepath, show_progress=False)
        except MemoryError:
            print(f"  Erreur mémoire sur {filepath} - fichier trop volumineux, ignoré")
        except Exception as e:
            print(f"Erreur lecture uptime {filepath}: {e}")
    
    def extract_year_from_date(self, date_str: str) -> Optional[str]:
        """Extrait l'année d'une date"""
        if not date_str or not isinstance(date_str, str):
            return None
        try:
            return date_str.split('-')[0] if '-' in date_str else None
        except:
            return None
    
    def get_6month_period(self, date: datetime) -> str:
        """Retourne la période de 6 mois au format 'YYYY-H1' ou 'YYYY-H2'"""
        year = date.year
        semester = 'H1' if date.month <= 6 else 'H2'
        return f"{year}-{semester}"
    
    def parse_date(self, date_str: str) -> Optional[datetime]:
        """Parse une date en datetime"""
        if not date_str:
            return None
        try:
            for fmt in ['%Y-%m-%d', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S']:
                try:
                    return datetime.strptime(date_str[:19], fmt)  # Limiter à 19 chars pour éviter les timezones
                except (ValueError, IndexError):
                    continue
        except:
            pass
        return None
    
    def process_domain_record(self, record: Dict) -> None:
        """
        Traite un enregistrement de domaine et met à jour les stats générales
        Ne stocke pas l'enregistrement complet, seulement les métriques
        NOTE: Les fichiers JSONL (années) ne contiennent PAS de données de transitions DNS temporelles.
        Les transitions DNS sont uniquement dans les fichiers uptimes/.
        Si un enregistrement JSONL contient un champ 'uptime', on le traite (rare).
        """
        # Vérifier si cet enregistrement contient des données uptime
        # (rare - certains JSONL pourraient avoir des données uptime intégrées)
        if 'uptime' in record:
            self.process_uptime_record(record)
        
        metadata = record.get('metadata', {})
        
        # Compter par année
        discovery_time = metadata.get('discovery_time')
        if discovery_time:
            if isinstance(discovery_time, int):
                year = str(datetime.fromtimestamp(discovery_time).year)
            else:
                year = self.extract_year_from_date(str(discovery_time))
            if year:
                self.stats['by_year'][year] += 1
        
        self.stats['total_domains'] += 1
        
        # Compter sources et targets
        src = metadata.get('src', 'unknown')
        trg = metadata.get('trg', 'unknown')
        if src:
            self.stats['sources'][src] += 1
        if trg:
            self.stats['targets'][trg] += 1
        
        # Analyser délai création → utilisation
        creation_date = None
        discovery_date = None
        
        # Chercher date de création
        if 'whois_bd' in record:
            cd = record['whois_bd'].get('cd')
            if cd:
                creation_date = self.parse_date(cd)
        
        # Chercher date de découverte
        if discovery_time:
            if isinstance(discovery_time, int):
                discovery_date = datetime.fromtimestamp(discovery_time)
            elif isinstance(discovery_time, str):
                discovery_date = self.parse_date(discovery_time)
        
        # Calculer délai si on a les deux dates
        if creation_date and discovery_date:
            delay = (discovery_date - creation_date).total_seconds() / 86400
            if 0 <= delay <= 36500:  # Filtrer les valeurs aberrantes (max 100 ans)
                self.stats['creation_to_usage_delays'].append({
                    'delay_days': delay,
                    'year': discovery_date.year if discovery_date else None
                })
    
    def process_uptime_record(self, record: Dict) -> None:
        """
        Traite un enregistrement uptime et met à jour les stats
        """
        if 'uptime' not in record:
            return
        
        uptime_entries = record.get('uptime', [])
        if not uptime_entries:
            return
        
        # Analyser transitions DNS
        dns_entries = [e for e in uptime_entries if e.get('type') == 'dns']
        if len(dns_entries) >= 2:
            dns_entries.sort(key=lambda x: self.parse_date(x.get('dt', '')) or datetime.min)
            
            # Chercher TOUTES les transitions NOERROR -> NXDOMAIN
            for i in range(len(dns_entries) - 1):
                current = dns_entries[i]
                next_entry = dns_entries[i + 1]
                
                current_status = current.get('dns_status', '')
                next_status = next_entry.get('dns_status', '')
                
                if current_status == 'NOERROR' and next_status == 'NXDOMAIN':
                    # Vérifier si ça reste NXDOMAIN (vérifier jusqu'à la fin ou 50 entrées max)
                    remains_nxdomain = True
                    check_limit = min(i + 50, len(dns_entries))
                    
                    # Vérifier les entrées suivantes
                    for j in range(i + 2, check_limit):
                        if dns_entries[j].get('dns_status') != 'NXDOMAIN':
                            remains_nxdomain = False
                            break
                    
                    # Si on a vérifié jusqu'à la fin et que tout est NXDOMAIN, c'est permanent
                    if remains_nxdomain and check_limit == len(dns_entries):
                        # Vérifier les 10 dernières entrées pour confirmer
                        last_entries = dns_entries[-10:] if len(dns_entries) >= 10 else dns_entries
                        if all(e.get('dns_status') == 'NXDOMAIN' for e in last_entries):
                            remains_nxdomain = True
                        else:
                            remains_nxdomain = False
                    
                    transition = {
                        'year': self.extract_year_from_date(next_entry.get('dt', '')),
                        'remains_nxdomain': remains_nxdomain,
                        'rd': record.get('rd', 'unknown'),
                        'sid': record.get('sid', 'unknown'),
                        'transition_date': next_entry.get('dt', ''),
                        'previous_date': current.get('dt', '')
                    }
                    
                    self.stats['dns_transitions'].append(transition)
                    if remains_nxdomain:
                        self.stats['nxdomain_permanent_count'] += 1
                    
                    # Extraire le domaine down dans le fichier JSONL séparé
                    if self.down_domains_file:
                        domain_info = {
                            'rd': record.get('rd', 'unknown'),
                            'fqdn': record.get('fqdn', 'unknown'),
                            'url': record.get('url', 'unknown'),
                            'sid': record.get('sid', 'unknown'),
                            'discovery_time': record.get('discovery_time', ''),
                            'dt': record.get('dt', ''),
                            'metadata': record.get('metadata', {}),
                            'transition': {
                                'transition_date': next_entry.get('dt', ''),
                                'previous_date': current.get('dt', ''),
                                'previous_status': current_status,
                                'new_status': next_status,
                                'remains_nxdomain': remains_nxdomain,
                                'year': transition['year']
                            },
                            'whois_bd': record.get('whois_bd', {}),
                            'takedown': record.get('takedown', {}),
                            # Garder une trace des entrées DNS autour de la transition (5 avant, 10 après)
                            'dns_context': {
                                'before': [{'dt': e.get('dt'), 'status': e.get('dns_status'), 'arec': e.get('arec', [])} 
                                          for e in dns_entries[max(0, i-5):i] if e.get('type') == 'dns'],
                                'transition_index': i,
                                'after': [{'dt': e.get('dt'), 'status': e.get('dns_status'), 'arec': e.get('arec', [])} 
                                         for e in dns_entries[i+1:min(len(dns_entries), i+11)] if e.get('type') == 'dns']
                            }
                        }
                        try:
                            self.down_domains_file.write(json.dumps(domain_info, ensure_ascii=False) + '\n')
                            self.down_domains_count += 1
                        except Exception as e:
                            # Si erreur d'écriture, continuer sans bloquer
                            print(f"\n  ⚠ Erreur écriture domaine down: {e}")
                    
                    # Extraire le domaine down dans le fichier JSONL séparé
                    if self.down_domains_file:
                        domain_info = {
                            'rd': record.get('rd', 'unknown'),
                            'fqdn': record.get('fqdn', 'unknown'),
                            'url': record.get('url', 'unknown'),
                            'sid': record.get('sid', 'unknown'),
                            'discovery_time': record.get('discovery_time', ''),
                            'metadata': record.get('metadata', {}),
                            'transition': {
                                'transition_date': next_entry.get('dt', ''),
                                'previous_date': current.get('dt', ''),
                                'previous_status': current_status,
                                'new_status': next_status,
                                'remains_nxdomain': remains_nxdomain,
                                'year': transition['year']
                            },
                            'whois_bd': record.get('whois_bd', {}),
                            'takedown': record.get('takedown', {}),
                            # Garder une trace des entrées DNS autour de la transition (10 avant, 20 après)
                            'dns_context': {
                                'before': [e for e in dns_entries[max(0, i-10):i] if e.get('type') == 'dns'],
                                'transition_index': i,
                                'after': [e for e in dns_entries[i+1:min(len(dns_entries), i+21)] if e.get('type') == 'dns']
                            }
                        }
                        self.down_domains_file.write(json.dumps(domain_info, ensure_ascii=False) + '\n')
                        self.down_domains_count += 1
        
        # Analyser changements WHOIS
        whois_entries = [e for e in uptime_entries if e.get('type') == 'whois']
        if len(whois_entries) >= 2:
            whois_entries.sort(key=lambda x: self.parse_date(x.get('dt', '')) or datetime.min)
            
            for i in range(len(whois_entries) - 1):
                current = whois_entries[i]
                next_entry = whois_entries[i + 1]
                
                if (current.get('whois_status') == 'active' and 
                    next_entry.get('whois_status') == 'inactive'):
                    self.stats['whois_changes'].append({
                        'year': self.extract_year_from_date(next_entry.get('dt', ''))
                    })
        
        # Analyser takedowns
        if 'takedown' in record:
            takedown = record.get('takedown', {})
            uptime_dur = takedown.get('uptime_dur')
            takedown_reason = takedown.get('takedown_reason', 'unknown')
            
            if uptime_dur is not None:
                discovery_time = record.get('discovery_time', '')
                year = self.extract_year_from_date(str(discovery_time))
                rd = record.get('rd', 'unknown')
                
                self.stats['takedown_durations'].append({
                    'duration_days': uptime_dur / 24,
                    'reason': takedown_reason,
                    'year': year,
                    'rd': rd  # Stocker le domaine pour pouvoir filtrer
                })
                self.stats['takedown_reasons'][takedown_reason] += 1
    
    def process_files_streaming(self, show_progress: bool = True):
        """
        Traite tous les fichiers en streaming (ligne par ligne)
        Ne charge jamais tout en mémoire
        
        Args:
            show_progress: Afficher les barres de progression
        """
        print("=" * 80)
        print("TRAITEMENT DES DONNÉES EN STREAMING (optimisé mémoire)")
        print("=" * 80)
        print("Recherche des fichiers à traiter...\n")
        
        # Ouvrir le fichier de sortie pour les domaines down (NOERROR → NXDOMAIN)
        down_domains_path = OUTPUT_DIR / 'down_domains.jsonl'
        self.down_domains_file = open(down_domains_path, 'w', encoding='utf-8')
        self.down_domains_count = 0
        print(f"📝 Fichier de sortie pour domaines down: {down_domains_path}\n")
        
        # Compter les fichiers à traiter
        all_files = []
        files_stats = {'jsonl': 0, 'uptime': 0, 'errors': []}
        
        # Traiter les fichiers JSONL seulement si on ne fait pas que les transitions DNS
        # Les fichiers JSONL servent pour les stats générales (domaines par année), pas pour les transitions DNS
        if not self.dns_only:
            # En mode échantillon, utiliser les fichiers dans sample_data/
            if self.sample_mode and SAMPLE_DATA_DIR.exists():
                # Chercher les fichiers d'échantillon
                sample_files = sorted(SAMPLE_DATA_DIR.glob("*.jsonl"))
                for sample_file in sample_files:
                    if sample_file.stat().st_size == 0:
                        continue
                    all_files.append(('jsonl', None, sample_file))
                    files_stats['jsonl'] += 1
            else:
                # Mode normal : chercher dans les répertoires d'années
                years = ['2022', '2023', '2024', '2025']
                for year in years:
                    year_dir = DATA_DIR / year
                    if year_dir.exists():
                        # Chercher les fichiers .jsonl non compressés
                        jsonl_files = sorted(year_dir.glob("*.jsonl"))
                        for jsonl_file in jsonl_files:
                            # Ignorer les fichiers .jsonl.zst (on les traitera séparément)
                            if str(jsonl_file).endswith('.zst'):
                                continue
                            # Ignorer les fichiers vides
                            if jsonl_file.stat().st_size == 0:
                                if not show_progress or not HAS_TQDM:
                                    print(f"  ⚠ {jsonl_file.name}: fichier vide, ignoré")
                                continue
                            
                            file_id = f"{year}/{jsonl_file.name}"
                            if file_id not in self._processed_files:
                                # Les fichiers JSONL servent seulement pour les stats générales, pas pour les transitions DNS
                                all_files.append(('jsonl', year, jsonl_file))
                                files_stats['jsonl'] += 1
                    
                    # Chercher aussi dans __{year}/ pour les fichiers compressés
                    compressed_dir = DATA_DIR / f"__{year}"
                    if compressed_dir.exists():
                        zst_files = sorted(compressed_dir.glob("*.jsonl.zst")) + sorted(compressed_dir.glob("*.zst"))
                        for zst_file in zst_files:
                            # Ignorer les fichiers vides
                            if zst_file.stat().st_size == 0:
                                continue
                            
                            # Déterminer le nom du fichier cible (sans le .zst et sans (1))
                            base_name = zst_file.name.replace('.zst', '').replace('(1)', '')
                            file_id = f"{year}/{base_name}"
                            
                            # Vérifier si le fichier décompressé existe déjà (priorité au fichier non compressé)
                            decompressed_path = year_dir / base_name
                            if decompressed_path.exists() and decompressed_path.stat().st_size > 0:
                                # Le fichier décompressé existe, on le traitera normalement
                                continue
                            
                            if file_id not in self._processed_files:
                                all_files.append(('jsonl', year, zst_file))
                                files_stats['jsonl'] += 1
        
        # Traiter les fichiers uptimes pour les transitions DNS (toujours)
        # Ces fichiers contiennent les données temporelles des transitions DNS
        # En mode échantillon, utiliser sample.json si disponible
        if self.sample_mode and SAMPLE_DATA_DIR.exists():
            sample_uptime = SAMPLE_DATA_DIR / "uptime_sample.json"
            if not sample_uptime.exists():
                sample_uptime = DATA_DIR / "uptimes" / "sample.json"
            if sample_uptime.exists():
                all_files.append(('uptime', None, sample_uptime))
                files_stats['uptime'] += 1
        else:
            uptimes_dir = DATA_DIR / "uptimes"
            if uptimes_dir.exists():
                # Chercher les fichiers JSON non compressés
                uptime_files = sorted(uptimes_dir.glob("*.json"))
                uptime_files_processed = set()
                
                for uptime_file in uptime_files:
                    if uptime_file.name not in ['schema.json', 'sample.json']:
                        # Vérifier qu'il n'y a pas de version compressée
                        zst_version = uptimes_dir / f"{uptime_file.name}.zst"
                        if not zst_version.exists():
                            all_files.append(('uptime', None, uptime_file))
                            uptime_files_processed.add(uptime_file.name)
                            files_stats['uptime'] += 1
                
                # Chercher les fichiers compressés .json.zst (pas juste .zst pour éviter les doublons)
                uptime_zst_files = sorted(uptimes_dir.glob("*.json.zst"))
                for uptime_file in uptime_zst_files:
                    # Ignorer les fichiers d'erreur et vérifier qu'on n'a pas déjà le fichier non compressé
                    if 'Error.txt' not in uptime_file.name:
                        base_name = uptime_file.name.replace('.zst', '')
                        if base_name not in uptime_files_processed:
                            all_files.append(('uptime', None, uptime_file))
                            files_stats['uptime'] += 1
        
        mode_str = "ÉCHANTILLON" if self.sample_mode else "COMPLET"
        print(f"[Mode {mode_str}] Fichiers trouvés: {files_stats['jsonl']} JSONL, {files_stats['uptime']} Uptime")
        print(f"Total fichiers à traiter: {len(all_files)}\n")
        print("-" * 80)
        
        # Statistiques de traitement
        stats = {
            'total_domains': 0,
            'total_uptimes': 0,
            'total_transitions': 0,
            'files_processed': 0,
            'files_skipped': 0,
            'files_errors': 0
        }
        
        # Traiter avec barre de progression globale
        main_iterator = all_files
        if show_progress and HAS_TQDM:
            main_iterator = tqdm(all_files, desc="🔄 Traitement", unit=" fichier", 
                                bar_format='{desc}: {percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}] {postfix}',
                                ncols=120, dynamic_ncols=False)
        
        for file_type, year, filepath in main_iterator:
            file_id = f"{year}/{filepath.name}" if year else filepath.name
            
            if file_type == 'jsonl':
                if file_id in self._processed_files:
                    continue
                
                count = 0
                transitions_before = len(self.stats['dns_transitions'])
                try:
                    for record in self.parse_jsonl_stream(filepath, show_progress=show_progress):
                        self.process_domain_record(record)
                        count += 1
                        
                        # Libérer mémoire périodiquement et mettre à jour la progression
                        if count % CHUNK_SIZE == 0:
                            gc.collect()
                            # Mise à jour périodique de la barre de progression avec valeurs estimées
                            if show_progress and HAS_TQDM and hasattr(main_iterator, 'set_postfix'):
                                estimated_transitions = len(self.stats['dns_transitions']) - transitions_before
                                main_iterator.set_postfix({
                                    'domaines': f"{stats['total_domains'] + count:,}",
                                    'transitions': f"{stats['total_transitions'] + estimated_transitions:,}"
                                }, refresh=True)
                    
                    transitions_after = len(self.stats['dns_transitions'])
                    transitions_found = transitions_after - transitions_before
                    
                    self._processed_files.add(file_id)
                    stats['files_processed'] += 1
                    stats['total_domains'] += count
                    stats['total_transitions'] += transitions_found
                    
                    if show_progress and HAS_TQDM:
                        # Mettre à jour la description de la barre de progression
                        if hasattr(main_iterator, 'set_postfix'):
                            main_iterator.set_postfix({
                                'domaines': f"{stats['total_domains']:,}",
                                'transitions': f"{stats['total_transitions']:,}"
                            }, refresh=True)
                    else:
                        print(f"  ✓ {file_id}: {count} domaines, {transitions_found} transitions DNS")
                    
                except MemoryError as e:
                    error_msg = f"Mémoire saturée sur {file_id}"
                    stats['files_errors'] += 1
                    files_stats['errors'].append((file_id, error_msg))
                    print(f"\n  ✗ {error_msg}")
                    print(f"     → Fichier ignoré pour éviter le crash système")
                    gc.collect()
                except KeyboardInterrupt:
                    print(f"\n\n⚠️  INTERRUPTION MANUELLE par l'utilisateur")
                    print(f"   Fichiers traités: {stats['files_processed']}/{len(all_files)}")
                    raise
                except FileNotFoundError as e:
                    error_msg = f"Fichier non trouvé: {filepath}"
                    stats['files_errors'] += 1
                    files_stats['errors'].append((file_id, str(e)))
                    print(f"\n  ✗ {error_msg}")
                    print(f"     → {e}")
                except subprocess.CalledProcessError as e:
                    error_msg = f"Erreur décompression zstd sur {file_id}"
                    stats['files_errors'] += 1
                    files_stats['errors'].append((file_id, str(e)))
                    print(f"\n  ✗ {error_msg}")
                    print(f"     → Vérifiez que zstd est installé et fonctionnel")
                except json.JSONDecodeError as e:
                    error_msg = f"Erreur JSON sur {file_id} (ligne probablement corrompue)"
                    stats['files_skipped'] += 1
                    print(f"\n  ⚠ {error_msg}")
                    print(f"     → Continuation avec les autres fichiers")
                except Exception as e:
                    error_msg = f"Erreur inattendue sur {file_id}"
                    stats['files_errors'] += 1
                    files_stats['errors'].append((file_id, str(e)))
                    import traceback
                    print(f"\n  ✗ {error_msg}")
                    print(f"     → {type(e).__name__}: {e}")
                    if not show_progress:  # Afficher la traceback seulement en mode non-progress
                        traceback.print_exc()
            
            elif file_type == 'uptime':
                # Ignorer les fichiers vides
                if filepath.stat().st_size == 0:
                    stats['files_skipped'] += 1
                    print(f"\n  ⚠ {filepath.name}: fichier vide, ignoré")
                    continue
                
                count = 0
                transitions_before = len(self.stats['dns_transitions'])
                try:
                    for record in self.parse_uptime_stream(filepath):
                        self.process_uptime_record(record)
                        count += 1
                        
                        if count % CHUNK_SIZE == 0:
                            gc.collect()
                            # Mise à jour périodique de la barre de progression avec valeurs estimées
                            if show_progress and HAS_TQDM and hasattr(main_iterator, 'set_postfix'):
                                estimated_transitions = len(self.stats['dns_transitions']) - transitions_before
                                main_iterator.set_postfix({
                                    'uptimes': f"{stats['total_uptimes'] + count:,}",
                                    'transitions': f"{stats['total_transitions'] + estimated_transitions:,}"
                                }, refresh=True)
                    
                    transitions_after = len(self.stats['dns_transitions'])
                    transitions_found = transitions_after - transitions_before
                    
                    stats['files_processed'] += 1
                    stats['total_uptimes'] += count
                    stats['total_transitions'] += transitions_found
                    
                    if show_progress and HAS_TQDM:
                        if hasattr(main_iterator, 'set_postfix'):
                            main_iterator.set_postfix({
                                'uptimes': f"{stats['total_uptimes']:,}",
                                'transitions': f"{stats['total_transitions']:,}"
                            }, refresh=True)
                    else:
                        print(f"  ✓ {filepath.name}: {count} uptimes, {transitions_found} transitions DNS")
                    
                except MemoryError as e:
                    error_msg = f"Mémoire saturée sur {filepath.name}"
                    stats['files_errors'] += 1
                    files_stats['errors'].append((filepath.name, error_msg))
                    print(f"\n  ✗ {error_msg}")
                    print(f"     → Fichier ignoré pour éviter le crash système")
                    gc.collect()
                except KeyboardInterrupt:
                    print(f"\n\n⚠️  INTERRUPTION MANUELLE par l'utilisateur")
                    print(f"   Fichiers traités: {stats['files_processed']}/{len(all_files)}")
                    raise
                except FileNotFoundError as e:
                    error_msg = f"Fichier non trouvé: {filepath}"
                    stats['files_errors'] += 1
                    files_stats['errors'].append((filepath.name, str(e)))
                    print(f"\n  ✗ {error_msg}")
                except subprocess.CalledProcessError as e:
                    error_msg = f"Erreur décompression zstd sur {filepath.name}"
                    stats['files_errors'] += 1
                    files_stats['errors'].append((filepath.name, str(e)))
                    print(f"\n  ✗ {error_msg}")
                    print(f"     → Vérifiez que zstd est installé et fonctionnel")
                except json.JSONDecodeError as e:
                    error_msg = f"Erreur JSON sur {filepath.name} (ligne probablement corrompue)"
                    stats['files_skipped'] += 1
                    print(f"\n  ⚠ {error_msg}")
                    print(f"     → Continuation avec les autres fichiers")
                except Exception as e:
                    error_msg = f"Erreur inattendue sur {filepath.name}"
                    stats['files_errors'] += 1
                    files_stats['errors'].append((filepath.name, str(e)))
                    import traceback
                    print(f"\n  ✗ {error_msg}")
                    print(f"     → {type(e).__name__}: {e}")
                    if not show_progress:  # Afficher la traceback seulement en mode non-progress
                        traceback.print_exc()
        
        # Fermer le fichier des domaines down
        if self.down_domains_file:
            self.down_domains_file.close()
            down_domains_path = OUTPUT_DIR / 'down_domains.jsonl'
            file_size = down_domains_path.stat().st_size if down_domains_path.exists() else 0
            print(f"\n✓ {self.down_domains_count:,} domaines down extraits dans: {down_domains_path} ({file_size / 1024 / 1024:.1f} MB)")
            
            # Créer un fichier filtré avec seulement les domaines malicieux (reste down)
            self._filter_malicious_domains(down_domains_path)
    
    def _filter_malicious_domains(self, down_domains_path: Path):
        """
        Filtre down_domains.jsonl pour ne garder que les domaines malicieux
        (reste down - remains_nxdomain = true)
        Ces domaines sont considérés comme malicieux et ont été down par le registrar.
        
        Crée un nouveau fichier: down_domains_malicious.jsonl
        """
        malicious_domains_path = OUTPUT_DIR / 'down_domains_malicious.jsonl'
        
        if not down_domains_path.exists():
            print(f"  ⚠ Fichier {down_domains_path} non trouvé, impossible de filtrer")
            return
        
        print(f"\n📝 Filtrage des domaines malicieux (reste down)...")
        
        stats = {
            'total_read': 0,
            'malicious_count': 0,
            'legitimate_count': 0
        }
        
        try:
            with open(down_domains_path, 'r', encoding='utf-8') as f_in:
                with open(malicious_domains_path, 'w', encoding='utf-8') as f_out:
                    iterator = f_in
                    if HAS_TQDM:
                        # Estimer le nombre de lignes
                        try:
                            f_in.seek(0)
                            total_lines = sum(1 for _ in f_in)
                            f_in.seek(0)
                            iterator = tqdm(f_in, total=total_lines, desc="  Filtrage", 
                                          unit=" lignes", leave=False)
                        except:
                            pass
                    
                    for line in iterator:
                        line = line.strip()
                        if not line:
                            continue
                        
                        try:
                            record = json.loads(line)
                            stats['total_read'] += 1
                            
                            if not isinstance(record, dict):
                                continue
                            
                            transition = record.get('transition') or {}
                            if not isinstance(transition, dict):
                                continue
                            
                            remains_nxdomain = transition.get('remains_nxdomain', False)
                            
                            # Ne garder que les domaines malicieux (reste down)
                            if remains_nxdomain:
                                # Ajouter un champ pour indiquer qu'il s'agit d'un domaine malicieux
                                record['malicious'] = True
                                record['takedown_reason'] = 'registrar_takedown'
                                
                                f_out.write(json.dumps(record, ensure_ascii=False) + '\n')
                                stats['malicious_count'] += 1
                            else:
                                stats['legitimate_count'] += 1
                                
                        except (json.JSONDecodeError, Exception):
                            continue
            
            malicious_file_size = malicious_domains_path.stat().st_size if malicious_domains_path.exists() else 0
            print(f"  ✓ {stats['malicious_count']:,} domaines malicieux extraits dans: {malicious_domains_path} ({malicious_file_size / 1024 / 1024:.1f} MB)")
            print(f"    • Total lu: {stats['total_read']:,}")
            print(f"    • Malicieux (reste down): {stats['malicious_count']:,}")
            print(f"    • Légitimes (re-up): {stats['legitimate_count']:,}")
            
        except Exception as e:
            print(f"  ✗ Erreur lors du filtrage des domaines malicieux: {e}")
            import traceback
            traceback.print_exc()
    
    def generate_plots(self):
        """Génère tous les graphiques"""
        if not HAS_PLOTTING:
            print("Graphiques désactivés (dépendances manquantes)")
            return
        
        print("\n=== Génération des graphiques ===")
        
        try:
            # 1. Distribution des délais création → utilisation
            if self.stats['creation_to_usage_delays']:
                self._plot_creation_delays()
            
            # 2. Évolution temporelle par année
            self._plot_temporal_evolution()
            
            # 3. Transitions DNS NOERROR → NXDOMAIN
            if self.stats['dns_transitions']:
                self._plot_dns_transitions()
            
            # 4. Durées avant takedown
            if self.stats['takedown_durations']:
                self._plot_takedown_durations()
            
            # 5. Comparaison par année
            self._plot_year_comparison()
            
            # 6. Durée achat → takedown par période de 6 mois (si down_domains.jsonl existe)
            self._plot_takedown_duration_by_6months()
            
            print(f"Graphiques sauvegardés dans: {OUTPUT_DIR}")
            
        except Exception as e:
            print(f"Erreur lors de la génération des graphiques: {e}")
            import traceback
            traceback.print_exc()
    
    def _plot_creation_delays(self):
        """Graphique distribution délais création → utilisation"""
        if not HAS_PLOTTING:
            return
        
        delays = [d['delay_days'] for d in self.stats['creation_to_usage_delays']]
        if not delays:
            return
        
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        fig.suptitle('Délais entre création du domaine et première utilisation malveillante', 
                     fontsize=16, fontweight='bold')
        
        # Histogramme global
        ax1 = axes[0, 0]
        ax1.hist(delays, bins=50, edgecolor='black', alpha=0.7)
        ax1.set_xlabel('Délai (jours)')
        ax1.set_ylabel('Nombre de domaines')
        ax1.set_title('Distribution globale des délais')
        median = np.median(delays)
        ax1.axvline(median, color='r', linestyle='--', 
                   label=f'Médiane: {median:.1f}j')
        ax1.legend()
        
        # Box plot par année
        ax2 = axes[0, 1]
        df = pd.DataFrame(self.stats['creation_to_usage_delays'])
        if 'year' in df.columns and len(df) > 0:
            years = sorted([y for y in df['year'].unique() if y])
            if years:
                data_by_year = [df[df['year'] == y]['delay_days'].values for y in years]
                bp = ax2.boxplot(data_by_year, labels=years, patch_artist=True)
                for patch in bp['boxes']:
                    patch.set_facecolor('lightblue')
                ax2.set_xlabel('Année')
                ax2.set_ylabel('Délai (jours)')
                ax2.set_title('Distribution par année')
                ax2.grid(True, alpha=0.3)
        
        # Distribution log
        ax3 = axes[1, 0]
        log_delays = [np.log10(d + 1) for d in delays]
        ax3.hist(log_delays, bins=50, edgecolor='black', alpha=0.7, color='green')
        ax3.set_xlabel('log10(Délai + 1) jours')
        ax3.set_ylabel('Nombre de domaines')
        ax3.set_title('Distribution logarithmique')
        
        # Statistiques cumulatives
        ax4 = axes[1, 1]
        sorted_delays = np.sort(delays)
        percentiles = np.arange(0, 101, 1)
        delay_percentiles = np.percentile(delays, percentiles)
        ax4.plot(percentiles, delay_percentiles, linewidth=2)
        ax4.set_xlabel('Percentile')
        ax4.set_ylabel('Délai (jours)')
        ax4.set_title('Courbe cumulative')
        ax4.grid(True, alpha=0.3)
        ax4.axhline(median, color='r', linestyle='--', alpha=0.5)
        
        plt.tight_layout()
        suffix = self._get_filename_suffix()
        plt.savefig(OUTPUT_DIR / f'creation_delays{suffix}.png', dpi=300, bbox_inches='tight')
        plt.close()
        gc.collect()
    
    def _plot_temporal_evolution(self):
        """Évolution temporelle des métriques"""
        if not HAS_PLOTTING:
            return
        
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        fig.suptitle('Évolution temporelle (2022-2025)', fontsize=16, fontweight='bold')
        
        # Domaines par année
        ax1 = axes[0, 0]
        years = sorted(self.stats['by_year'].keys())
        counts = [self.stats['by_year'][y] for y in years]
        if years:
            ax1.bar(years, counts, color='steelblue', alpha=0.7, edgecolor='black')
            ax1.set_xlabel('Année')
            ax1.set_ylabel('Nombre de domaines')
            ax1.set_title('Domaines malveillants par année')
            ax1.grid(True, alpha=0.3, axis='y')
        
        # Transitions DNS par année
        ax2 = axes[0, 1]
        if self.stats['dns_transitions']:
            df_trans = pd.DataFrame(self.stats['dns_transitions'])
            if 'year' in df_trans.columns and len(df_trans) > 0:
                trans_by_year = df_trans['year'].value_counts().sort_index()
                if len(trans_by_year) > 0:
                    ax2.bar(trans_by_year.index, trans_by_year.values, 
                           color='coral', alpha=0.7, edgecolor='black')
                    ax2.set_xlabel('Année')
                    ax2.set_ylabel('Nombre de transitions')
                    ax2.set_title('Transitions NOERROR → NXDOMAIN par année')
                    ax2.grid(True, alpha=0.3, axis='y')
        
        # Délais moyens par année
        ax3 = axes[1, 0]
        if self.stats['creation_to_usage_delays']:
            df_delays = pd.DataFrame(self.stats['creation_to_usage_delays'])
            if 'year' in df_delays.columns and len(df_delays) > 0:
                delays_by_year = df_delays.groupby('year')['delay_days'].agg(['mean', 'median'])
                if len(delays_by_year) > 0:
                    x = delays_by_year.index
                    ax3.plot(x, delays_by_year['mean'], marker='o', label='Moyenne', linewidth=2)
                    ax3.plot(x, delays_by_year['median'], marker='s', label='Médiane', linewidth=2)
                    ax3.set_xlabel('Année')
                    ax3.set_ylabel('Délai (jours)')
                    ax3.set_title('Délai moyen création → utilisation par année')
                    ax3.legend()
                    ax3.grid(True, alpha=0.3)
        
        # Takedowns par année (domaines restant down uniquement)
        ax4 = axes[1, 1]
        if self.stats['takedown_durations']:
            # Filtrer pour ne garder que les domaines qui restent down
            domains_that_remain_down = set()
            for transition in self.stats['dns_transitions']:
                if transition.get('remains_nxdomain', False):
                    domains_that_remain_down.add(transition.get('rd', ''))
            
            filtered_takedowns = [d for d in self.stats['takedown_durations'] 
                                 if d.get('rd', '') in domains_that_remain_down]
            
            if filtered_takedowns:
                df_takedown = pd.DataFrame(filtered_takedowns)
                if 'year' in df_takedown.columns and len(df_takedown) > 0:
                    takedown_by_year = df_takedown['year'].value_counts().sort_index()
                    if len(takedown_by_year) > 0:
                        ax4.bar(takedown_by_year.index, takedown_by_year.values,
                               color='mediumseagreen', alpha=0.7, edgecolor='black')
                        ax4.set_xlabel('Année')
                        ax4.set_ylabel('Nombre de takedowns')
                        ax4.set_title('Takedowns par année (domaines restant down)')
                        ax4.grid(True, alpha=0.3, axis='y')
        
        plt.tight_layout()
        suffix = self._get_filename_suffix()
        plt.savefig(OUTPUT_DIR / f'temporal_evolution{suffix}.png', dpi=300, bbox_inches='tight')
        plt.close()
        gc.collect()
    
    def _plot_dns_transitions(self):
        """Graphique transitions DNS"""
        if not HAS_PLOTTING or not self.stats['dns_transitions']:
            return
        
        fig, axes = plt.subplots(1, 2, figsize=(14, 6))
        fig.suptitle('Transitions DNS NOERROR → NXDOMAIN', fontsize=16, fontweight='bold')
        
        df = pd.DataFrame(self.stats['dns_transitions'])
        
        # Transitions permanentes vs temporaires
        ax1 = axes[0]
        permanent_count = self.stats['nxdomain_permanent_count']
        temp_count = len(self.stats['dns_transitions']) - permanent_count
        if permanent_count + temp_count > 0:
            ax1.pie([permanent_count, temp_count], 
                   labels=['Permanentes\n(reste NXDOMAIN)', 'Temporaires'],
                   autopct='%1.1f%%', startangle=90, colors=['#ff6b6b', '#4ecdc4'])
            ax1.set_title('Proportion transitions permanentes')
        
        # Par année
        ax2 = axes[1]
        if 'year' in df.columns and len(df) > 0:
            trans_by_year = df['year'].value_counts().sort_index()
            permanent_by_year = df[df['remains_nxdomain']]['year'].value_counts().sort_index()
            
            if len(trans_by_year) > 0:
                x = trans_by_year.index
                width = 0.35
                x_pos = np.arange(len(x))
                
                ax2.bar(x_pos - width/2, [trans_by_year.get(y, 0) for y in x],
                       width, label='Total transitions', alpha=0.7, color='steelblue')
                ax2.bar(x_pos + width/2, [permanent_by_year.get(y, 0) for y in x],
                       width, label='Permanentes', alpha=0.7, color='coral')
                ax2.set_xlabel('Année')
                ax2.set_ylabel('Nombre')
                ax2.set_title('Transitions par année')
                ax2.set_xticks(x_pos)
                ax2.set_xticklabels(x)
                ax2.legend()
                ax2.grid(True, alpha=0.3, axis='y')
        
        plt.tight_layout()
        suffix = self._get_filename_suffix()
        plt.savefig(OUTPUT_DIR / f'dns_transitions{suffix}.png', dpi=300, bbox_inches='tight')
        plt.close()
        gc.collect()
    
    def _plot_takedown_durations(self):
        """
        Graphique durées avant takedown
        Filtre pour ne garder que les domaines qui restent down (remains_nxdomain = true)
        """
        if not HAS_PLOTTING or not self.stats['takedown_durations']:
            return
        
        # Créer un set des domaines qui restent down (remains_nxdomain = true)
        domains_that_remain_down = set()
        for transition in self.stats['dns_transitions']:
            if transition.get('remains_nxdomain', False):
                domains_that_remain_down.add(transition.get('rd', ''))
        
        # Filtrer les takedown_durations pour ne garder que ceux qui restent down
        filtered_durations = []
        for d in self.stats['takedown_durations']:
            rd = d.get('rd', '')
            if rd in domains_that_remain_down:
                filtered_durations.append(d)
        
        if not filtered_durations:
            print("  ⚠ Aucun takedown avec domaine restant down, graphique ignoré")
            return
        
        durations = [d['duration_days'] for d in filtered_durations]
        if not durations:
            return
        
        fig, axes = plt.subplots(1, 2, figsize=(14, 6))
        fig.suptitle('Durées avant takedown (domaines restant down uniquement)', 
                     fontsize=16, fontweight='bold')
        
        # Histogramme
        ax1 = axes[0]
        ax1.hist(durations, bins=50, edgecolor='black', alpha=0.7, color='mediumseagreen')
        ax1.set_xlabel('Durée (jours)')
        ax1.set_ylabel('Nombre de domaines')
        ax1.set_title('Distribution des durées avant takedown')
        median = np.median(durations)
        ax1.axvline(median, color='r', linestyle='--',
                   label=f'Médiane: {median:.1f}j')
        ax1.legend()
        ax1.grid(True, alpha=0.3, axis='y')
        
        # Par raison de takedown (filtré)
        ax2 = axes[1]
        # Recompter les raisons pour les domaines filtrés
        filtered_reasons = Counter([d['reason'] for d in filtered_durations])
        if filtered_reasons:
            reasons = dict(filtered_reasons.most_common(10))  # Top 10
            if reasons:
                ax2.barh(list(reasons.keys()), list(reasons.values()), 
                        alpha=0.7, color='coral', edgecolor='black')
                ax2.set_xlabel('Nombre de takedowns')
                ax2.set_title('Takedowns par raison - Domaines restant down (Top 10)')
                ax2.grid(True, alpha=0.3, axis='x')
        
        plt.tight_layout()
        suffix = self._get_filename_suffix()
        plt.savefig(OUTPUT_DIR / f'takedown_durations{suffix}.png', dpi=300, bbox_inches='tight')
        plt.close()
        gc.collect()
    
    def _plot_year_comparison(self):
        """Comparaison détaillée par année"""
        if not HAS_PLOTTING:
            return
        
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        fig.suptitle('Comparaison par année (2022-2025)', fontsize=16, fontweight='bold')
        
        years = sorted([y for y in self.stats['by_year'].keys() if y])
        if not years:
            plt.close()
            return
        
        # 1. Nombre total de domaines
        ax1 = axes[0, 0]
        counts = [self.stats['by_year'][y] for y in years]
        ax1.bar(years, counts, color='steelblue', alpha=0.7, edgecolor='black')
        ax1.set_xlabel('Année')
        ax1.set_ylabel('Nombre de domaines')
        ax1.set_title('Volume total par année')
        ax1.grid(True, alpha=0.3, axis='y')
        
        # 2. Délais moyens
        ax2 = axes[0, 1]
        if self.stats['creation_to_usage_delays']:
            df = pd.DataFrame(self.stats['creation_to_usage_delays'])
            if 'year' in df.columns and len(df) > 0:
                delays_by_year = df.groupby('year')['delay_days'].mean()
                available_years = [y for y in years if y in delays_by_year.index]
                if available_years:
                    ax2.plot(available_years, [delays_by_year[y] for y in available_years],
                            marker='o', linewidth=2, markersize=8, color='coral')
                    ax2.set_xlabel('Année')
                    ax2.set_ylabel('Délai moyen (jours)')
                    ax2.set_title('Délai moyen création → utilisation')
                    ax2.grid(True, alpha=0.3)
        
        # 3. Taux de transitions permanentes
        ax3 = axes[1, 0]
        if self.stats['dns_transitions']:
            df = pd.DataFrame(self.stats['dns_transitions'])
            if 'year' in df.columns and len(df) > 0:
                rates = []
                for year in years:
                    year_trans = df[df['year'] == year]
                    if len(year_trans) > 0:
                        permanent = sum(year_trans['remains_nxdomain'])
                        rate = (permanent / len(year_trans)) * 100
                        rates.append(rate)
                    else:
                        rates.append(0)
                ax3.bar(years, rates, color='mediumseagreen', alpha=0.7, edgecolor='black')
                ax3.set_xlabel('Année')
                ax3.set_ylabel('Taux (%)')
                ax3.set_title('% Transitions permanentes (NOERROR → NXDOMAIN)')
                ax3.grid(True, alpha=0.3, axis='y')
        
        # 4. Durées moyennes takedown (domaines restant down uniquement)
        ax4 = axes[1, 1]
        if self.stats['takedown_durations']:
            # Filtrer pour ne garder que les domaines qui restent down
            domains_that_remain_down = set()
            for transition in self.stats['dns_transitions']:
                if transition.get('remains_nxdomain', False):
                    domains_that_remain_down.add(transition.get('rd', ''))
            
            filtered_takedowns = [d for d in self.stats['takedown_durations'] 
                                 if d.get('rd', '') in domains_that_remain_down]
            
            if filtered_takedowns:
                df = pd.DataFrame(filtered_takedowns)
                if 'year' in df.columns and len(df) > 0:
                    takedown_by_year = df.groupby('year')['duration_days'].mean()
                    available_years = [y for y in years if y in takedown_by_year.index]
                    if available_years:
                        ax4.bar(available_years, [takedown_by_year[y] for y in available_years],
                               color='gold', alpha=0.7, edgecolor='black')
                        ax4.set_xlabel('Année')
                        ax4.set_ylabel('Durée moyenne (jours)')
                        ax4.set_title('Durée moyenne avant takedown (domaines restant down)')
                        ax4.grid(True, alpha=0.3, axis='y')
        
        plt.tight_layout()
        suffix = self._get_filename_suffix()
        plt.savefig(OUTPUT_DIR / f'year_comparison{suffix}.png', dpi=300, bbox_inches='tight')
        plt.close()
        gc.collect()
    
    def _plot_takedown_duration_by_6months(self):
        """
        Graphique de la durée entre achat et takedown (NOERROR → NXDOMAIN)
        par période de 6 mois, pour les domaines down pour des raisons illégitimes.
        
        Lit le fichier down_domains.jsonl généré précédemment.
        """
        if not HAS_PLOTTING:
            return
        
        down_domains_file = OUTPUT_DIR / 'down_domains.jsonl'
        if not down_domains_file.exists():
            print("  ⚠ Fichier down_domains.jsonl non trouvé, graphique par période 6 mois ignoré")
            return
        
        print("  📊 Génération graphique durée achat→takedown par période 6 mois...")
        
        # Traiter le fichier en streaming
        durations_by_period = defaultdict(list)
        stats = {
            'total_processed': 0,
            'valid_durations': 0,
            'illegitimate_takedowns': 0
        }
        
        try:
            with open(down_domains_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        record = json.loads(line)
                        stats['total_processed'] += 1
                        
                        if not isinstance(record, dict):
                            continue
                        
                        # Filtrer les domaines down pour des raisons illégitimes
                        transition = record.get('transition') or {}
                        if not isinstance(transition, dict):
                            continue
                        
                        remains_nxdomain = transition.get('remains_nxdomain', False)
                        if not remains_nxdomain:
                            continue  # Ignorer les takedowns légitimes (re-up)
                        
                        stats['illegitimate_takedowns'] += 1
                        
                        # Extraire la date de création
                        whois_bd = record.get('whois_bd') or {}
                        if not isinstance(whois_bd, dict):
                            continue
                        creation_date_str = whois_bd.get('cd', '')
                        creation_date = self.parse_date(creation_date_str) if creation_date_str else None
                        
                        if not creation_date:
                            continue
                        
                        # Extraire la date de transition (takedown)
                        transition_date_str = transition.get('transition_date', '')
                        transition_date = self.parse_date(transition_date_str) if transition_date_str else None
                        
                        if not transition_date:
                            continue
                        
                        # Calculer la durée en jours
                        duration_days = (transition_date - creation_date).total_seconds() / 86400
                        
                        # Filtrer les valeurs aberrantes
                        if duration_days < 0 or duration_days > 18250:  # 50 ans max
                            continue
                        
                        stats['valid_durations'] += 1
                        
                        # Grouper par période de 6 mois
                        period = self.get_6month_period(transition_date)
                        durations_by_period[period].append(duration_days)
                        
                    except (json.JSONDecodeError, Exception):
                        continue
            
            if not durations_by_period:
                print("  ⚠ Aucune donnée valide pour le graphique par période 6 mois")
                return
            
            # Préparer les données
            data = []
            for period, durations in sorted(durations_by_period.items()):
                data.append({
                    'period': period,
                    'durations': durations,
                    'count': len(durations),
                    'mean': np.mean(durations),
                    'median': np.median(durations),
                    'p25': np.percentile(durations, 25),
                    'p75': np.percentile(durations, 75)
                })
            
            periods = [d['period'] for d in data]
            means = [d['mean'] for d in data]
            medians = [d['median'] for d in data]
            counts = [d['count'] for d in data]
            p25s = [d['p25'] for d in data]
            p75s = [d['p75'] for d in data]
            
            # Créer la figure
            fig, axes = plt.subplots(2, 2, figsize=(16, 12))
            fig.suptitle('Durée entre achat et takedown (NOERROR → NXDOMAIN)\nDomaines down pour raisons illégitimes - Par période de 6 mois',
                         fontsize=16, fontweight='bold')
            
            # 1. Durée moyenne par période
            ax1 = axes[0, 0]
            x_pos = np.arange(len(periods))
            width = 0.35
            
            ax1.bar(x_pos - width/2, means, width, label='Moyenne', alpha=0.7, color='steelblue', edgecolor='black')
            ax1.bar(x_pos + width/2, medians, width, label='Médiane', alpha=0.7, color='coral', edgecolor='black')
            
            ax1.set_xlabel('Période (6 mois)')
            ax1.set_ylabel('Durée (jours)')
            ax1.set_title('Durée moyenne et médiane par période')
            ax1.set_xticks(x_pos)
            ax1.set_xticklabels(periods, rotation=45, ha='right')
            ax1.legend()
            ax1.grid(True, alpha=0.3, axis='y')
            
            # Ajouter les valeurs sur les barres
            for i, (mean, median) in enumerate(zip(means, medians)):
                ax1.text(i - width/2, mean, f'{mean:.0f}', ha='center', va='bottom', fontsize=8)
                ax1.text(i + width/2, median, f'{median:.0f}', ha='center', va='bottom', fontsize=8)
            
            # 2. Box plot ou histogramme global
            ax2 = axes[0, 1]
            if len(periods) <= 20:
                box_data = [d['durations'] for d in data]
                bp = ax2.boxplot(box_data, labels=periods, patch_artist=True, showfliers=False)
                for patch in bp['boxes']:
                    patch.set_facecolor('lightblue')
                ax2.set_xlabel('Période (6 mois)')
                ax2.set_ylabel('Durée (jours)')
                ax2.set_title('Distribution des durées par période (box plot)')
                ax2.tick_params(axis='x', rotation=45)
                ax2.grid(True, alpha=0.3, axis='y')
            else:
                all_durations = []
                for d in data:
                    all_durations.extend(d['durations'])
                ax2.hist(all_durations, bins=50, edgecolor='black', alpha=0.7, color='lightblue')
                ax2.set_xlabel('Durée (jours)')
                ax2.set_ylabel('Nombre de domaines')
                ax2.set_title('Distribution globale des durées')
                median_global = np.median(all_durations)
                ax2.axvline(median_global, color='r', linestyle='--', 
                           label=f'Médiane globale: {median_global:.1f}j')
                ax2.legend()
                ax2.grid(True, alpha=0.3, axis='y')
            
            # 3. Nombre de domaines par période
            ax3 = axes[1, 0]
            ax3.bar(x_pos, counts, alpha=0.7, color='mediumseagreen', edgecolor='black')
            ax3.set_xlabel('Période (6 mois)')
            ax3.set_ylabel('Nombre de domaines')
            ax3.set_title('Nombre de takedowns illégitimes par période')
            ax3.set_xticks(x_pos)
            ax3.set_xticklabels(periods, rotation=45, ha='right')
            ax3.grid(True, alpha=0.3, axis='y')
            
            for i, count in enumerate(counts):
                ax3.text(i, count, f'{count:,}', ha='center', va='bottom', fontsize=8)
            
            # 4. Évolution de la durée médiane
            ax4 = axes[1, 1]
            ax4.plot(x_pos, medians, marker='o', linewidth=2, markersize=8, color='coral', label='Médiane')
            ax4.fill_between(x_pos, p25s, p75s, alpha=0.3, color='coral', label='Q1-Q3')
            ax4.set_xlabel('Période (6 mois)')
            ax4.set_ylabel('Durée (jours)')
            ax4.set_title('Évolution de la durée médiane (avec quartiles)')
            ax4.set_xticks(x_pos)
            ax4.set_xticklabels(periods, rotation=45, ha='right')
            ax4.legend()
            ax4.grid(True, alpha=0.3)
            
            plt.tight_layout()
            suffix = self._get_filename_suffix()
            plt.savefig(OUTPUT_DIR / f'takedown_duration_by_6months{suffix}.png', dpi=300, bbox_inches='tight')
            plt.close()
            gc.collect()
            
            # Générer le résumé textuel
            summary_path = OUTPUT_DIR / 'takedown_duration_by_6months_summary.txt'
            with open(summary_path, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write("DURÉE ENTRE ACHAT ET TAKEDOWN PAR PÉRIODE DE 6 MOIS\n")
                f.write("Domaines down pour raisons illégitimes (reste NXDOMAIN)\n")
                f.write("=" * 80 + "\n\n")
                
                f.write(f"{'Période':<15} {'Nb domaines':<15} {'Moyenne (j)':<15} {'Médiane (j)':<15} {'Q1 (j)':<15} {'Q3 (j)':<15}\n")
                f.write("-" * 80 + "\n")
                
                for d in data:
                    f.write(f"{d['period']:<15} {d['count']:<15,} {d['mean']:<15.1f} {d['median']:<15.1f} "
                           f"{d['p25']:<15.1f} {d['p75']:<15.1f}\n")
                
                f.write("\n" + "=" * 80 + "\n")
                f.write(f"Total domaines analysés: {sum(counts):,}\n")
                f.write(f"Durée moyenne globale: {np.mean([d['mean'] for d in data]):.1f} jours\n")
                f.write(f"Durée médiane globale: {np.median([d['median'] for d in data]):.1f} jours\n")
                f.write("=" * 80 + "\n")
            
            suffix = self._get_filename_suffix()
            print(f"    ✓ Graphique: takedown_duration_by_6months{suffix}.png")
            print(f"    ✓ Résumé: takedown_duration_by_6months_summary.txt")
            
        except Exception as e:
            print(f"  ⚠ Erreur génération graphique par période 6 mois: {e}")
    
    def generate_report(self):
        """Génère un rapport textuel"""
        report_path = OUTPUT_DIR / 'analysis_report.txt'
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("RAPPORT D'ANALYSE - DOMAINES MALVEILLANTS\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"Date d'analyse: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("1. RÉSUMÉ GÉNÉRAL\n")
            f.write("-" * 80 + "\n")
            f.write(f"Total domaines analysés: {self.stats['total_domains']}\n")
            f.write(f"Domaines par année:\n")
            for year in sorted(self.stats['by_year'].keys()):
                f.write(f"  {year}: {self.stats['by_year'][year]}\n")
            f.write("\n")
            
            f.write("2. TRANSITIONS DNS NOERROR → NXDOMAIN\n")
            f.write("-" * 80 + "\n")
            f.write(f"Total transitions: {len(self.stats['dns_transitions'])}\n")
            f.write(f"Transitions permanentes (reste NXDOMAIN): {self.stats['nxdomain_permanent_count']}\n")
            if self.stats['dns_transitions']:
                permanent_rate = (self.stats['nxdomain_permanent_count'] / 
                                len(self.stats['dns_transitions'])) * 100
                f.write(f"Taux de permanence: {permanent_rate:.2f}%\n")
            f.write("\n")
            
            f.write("3. DÉLAIS CRÉATION → UTILISATION MALVEILLANTE\n")
            f.write("-" * 80 + "\n")
            if self.stats['creation_to_usage_delays']:
                delays = [d['delay_days'] for d in self.stats['creation_to_usage_delays']]
                f.write(f"Total délais calculés: {len(delays)}\n")
                if HAS_PLOTTING:
                    f.write(f"Délai moyen: {np.mean(delays):.2f} jours\n")
                    f.write(f"Délai médian: {np.median(delays):.2f} jours\n")
                    f.write(f"Délai min: {np.min(delays):.2f} jours\n")
                    f.write(f"Délai max: {np.max(delays):.2f} jours\n")
                    f.write(f"Écart-type: {np.std(delays):.2f} jours\n")
                    
                    immediate = sum(1 for d in delays if d < 1)
                    f.write(f"Domaines utilisés < 1 jour après création: {immediate} ({immediate/len(delays)*100:.1f}%)\n")
            f.write("\n")
            
            f.write("4. TAKEDOWNS (domaines restant down uniquement)\n")
            f.write("-" * 80 + "\n")
            # Filtrer pour ne garder que les domaines qui restent down
            domains_that_remain_down = set()
            for transition in self.stats['dns_transitions']:
                if transition.get('remains_nxdomain', False):
                    domains_that_remain_down.add(transition.get('rd', ''))
            
            filtered_takedowns = [d for d in self.stats['takedown_durations'] 
                                 if d.get('rd', '') in domains_that_remain_down]
            
            f.write(f"Total takedowns (tous domaines): {len(self.stats['takedown_durations'])}\n")
            f.write(f"Total takedowns (domaines restant down): {len(filtered_takedowns)}\n")
            if filtered_takedowns:
                durations = [d['duration_days'] for d in filtered_takedowns]
                if HAS_PLOTTING:
                    f.write(f"Durée moyenne: {np.mean(durations):.2f} jours\n")
                    f.write(f"Durée médian: {np.median(durations):.2f} jours\n")
                
                # Recompter les raisons pour les domaines filtrés
                filtered_reasons = Counter([d['reason'] for d in filtered_takedowns])
                f.write("Par raison (domaines restant down):\n")
                for reason, count in filtered_reasons.most_common():
                    f.write(f"  {reason}: {count}\n")
            f.write("\n")
            
            f.write("5. CHANGEMENTS WHOIS\n")
            f.write("-" * 80 + "\n")
            f.write(f"Changements active → inactive: {len(self.stats['whois_changes'])}\n")
            f.write("\n")
            
            f.write("6. SOURCES ET TARGETS\n")
            f.write("-" * 80 + "\n")
            f.write("Top 10 sources:\n")
            for src, count in self.stats['sources'].most_common(10):
                f.write(f"  {src}: {count}\n")
            f.write("\nTop 10 targets:\n")
            for trg, count in self.stats['targets'].most_common(10):
                f.write(f"  {trg}: {count}\n")
            f.write("\n")
            
            f.write("7. ÉVOLUTION TEMPORELLE\n")
            f.write("-" * 80 + "\n")
            if self.stats['creation_to_usage_delays'] and HAS_PLOTTING:
                df = pd.DataFrame(self.stats['creation_to_usage_delays'])
                if 'year' in df.columns:
                    f.write("Délais moyens par année:\n")
                    delays_by_year = df.groupby('year')['delay_days'].agg(['mean', 'count'])
                    for year in sorted(delays_by_year.index):
                        f.write(f"  {year}: {delays_by_year.loc[year, 'mean']:.2f} jours "
                               f"(n={delays_by_year.loc[year, 'count']})\n")
            f.write("\n")
            
            f.write("=" * 80 + "\n")
            f.write("FIN DU RAPPORT\n")
            f.write("=" * 80 + "\n")
        
        print(f"Rapport sauvegardé: {report_path}")
    
    def run_full_analysis(self, show_progress: bool = True):
        """Exécute l'analyse complète"""
        print("=" * 80)
        print("ANALYSE DES DOMAINES MALVEILLANTS (Version optimisée mémoire)")
        print("=" * 80)
        
        # Traiter les fichiers en streaming
        self.process_files_streaming(show_progress=show_progress)
        
        # Générer les visualisations
        if show_progress and HAS_TQDM:
            print("\nGénération des graphiques...")
        self.generate_plots()
        
        # Générer le rapport
        if show_progress and HAS_TQDM:
            print("Génération du rapport...")
        self.generate_report()
        
        print("\n" + "=" * 80)
        print("ANALYSE TERMINÉE")
        print("=" * 80)
        print(f"Résultats sauvegardés dans: {OUTPUT_DIR}")


def main():
    """Point d'entrée principal"""
    import sys
    
    # Vérifier si mode échantillon activé
    sample_mode = '--sample' in sys.argv or '-s' in sys.argv
    dns_only = '--dns-only' in sys.argv or '--dns' in sys.argv
    
    if sample_mode:
        print("=" * 80)
        print("MODE ÉCHANTILLON ACTIVÉ")
        print("Utilisation des fichiers dans sample_data/")
        print("=" * 80)
        print()
    
    if dns_only:
        print("=" * 80)
        print("MODE DNS-ONLY ACTIVÉ")
        print("Seulement les transitions DNS (fichiers uptimes/) seront analysées")
        print("Les fichiers JSONL (années) seront ignorés")
        print("=" * 80)
        print()
    
    analyzer = DomainAnalyzer(sample_mode=sample_mode, dns_only=dns_only)
    analyzer.run_full_analysis()


if __name__ == "__main__":
    main()
