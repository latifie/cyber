#!/usr/bin/env python3
"""
================================================================================
SCRIPT D'ANALYSE DES DOMAINES MALICIEUX - PROJET CYBER
================================================================================

Analyses spécialisées basées uniquement sur down_domains_malicious.jsonl
(domaines malicieux down par le registrar).

Analyses implémentées:
1. ✅ Durée achat → takedown par période 6 mois (déjà existant)
2. Analyse par type d'attaque (source) - metadata.src
3. Analyse par type d'attaque (target) - metadata.trg
4. Analyse par registraire (IANA ID) - whois_bd.iana_id
5. Analyse par TLD - metadata.tld
6. Durée découverte → takedown - discovery_time × transition.transition_date
7. Âge des domaines au takedown - whois_bd.cd × transition.transition_date
8. Changements d'IP avant takedown - dns_context.before[].arec

UTILISATION:
------------
python3 analyze_malicious_domains.py [--sample]

OUTPUTS:
--------
Graphiques (PNG, 300 DPI):
  Les noms de fichiers incluent un suffixe indiquant les options d'exécution:
  - _full : Analyse complète (toutes les données)
  - _sample : Mode échantillon (données d'échantillon)
  
  Exemples:
  - malicious_attack_source_analysis_full.png : Analyse complète
  - malicious_attack_source_analysis_sample.png : Même analyse en mode échantillon

AUTEUR: Analyse automatique
DATE: 2025
================================================================================
"""

import json
from pathlib import Path
from datetime import datetime
from collections import defaultdict, Counter
from typing import Dict, List, Optional
import warnings
warnings.filterwarnings('ignore')

# Import des librairies de visualisation
try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import pandas as pd
    import numpy as np
    HAS_PLOTTING = True
except ImportError:
    HAS_PLOTTING = False
    print("Erreur: matplotlib/pandas/numpy requis pour ce script")
    exit(1)

# Barre de progression
try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    def tqdm(iterable, *args, **kwargs):
        return iterable

# Configuration
DATA_DIR = Path(__file__).parent
OUTPUT_DIR = DATA_DIR / "analysis_results"
OUTPUT_DIR.mkdir(exist_ok=True)

MALICIOUS_DOMAINS_FILE = OUTPUT_DIR / 'down_domains_malicious.jsonl'


def parse_date(date_str: str) -> Optional[datetime]:
    """Parse une date en datetime"""
    if not date_str:
        return None
    try:
        for fmt in ['%Y-%m-%d', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S.%f']:
            try:
                date_part = date_str[:19] if len(date_str) > 19 else date_str
                return datetime.strptime(date_part, fmt)
            except (ValueError, IndexError):
                continue
    except:
        pass
    return None


def get_6month_period(date: datetime) -> str:
    """Retourne la période de 6 mois au format 'YYYY-H1' ou 'YYYY-H2'"""
    year = date.year
    semester = 'H1' if date.month <= 6 else 'H2'
    return f"{year}-{semester}"


def extract_year_from_date(date_str: str) -> Optional[str]:
    """Extrait l'année d'une date"""
    if not date_str or not isinstance(date_str, str):
        return None
    try:
        return date_str.split('-')[0] if '-' in date_str else None
    except:
        return None


class MaliciousDomainAnalyzer:
    """Analyseur spécialisé pour les domaines malicieux"""
    
    def __init__(self, sample_mode: bool = False):
        """
        Args:
            sample_mode: Si True, utilise les fichiers d'échantillon dans sample_data/
        """
        self.sample_mode = sample_mode
        
        # Stats pour les analyses
        self.stats = {
            # 2. Analyse par type d'attaque (source)
            'attack_source_delays': [],  # {src, delay_days, year}
            'attack_source_takedowns': [],  # {src, duration_days, year}
            
            # 3. Analyse par type d'attaque (target)
            'attack_target_delays': [],  # {trg, delay_days, year}
            'attack_target_takedowns': [],  # {trg, duration_days, year}
            
            # 4. Analyse par registraire
            'registrar_delays': [],  # {iana_id, delay_days, year}
            'registrar_takedowns': [],  # {iana_id, duration_days, year}
            
            # 5. Analyse par TLD
            'tld_delays': [],  # {tld, delay_days, year}
            'tld_takedowns': [],  # {tld, duration_days, year}
            
            # 6. Durée découverte → takedown
            'discovery_to_takedown': [],  # {duration_days, year}
            
            # 7. Âge des domaines au takedown
            'age_at_takedown': [],  # {age_days, year, category}
            
            # 8. Changements d'IP avant takedown
            'ip_changes': []  # {change_count, unique_ips, rd}
        }
    
    def _get_filename_suffix(self) -> str:
        """
        Génère un suffixe pour les noms de fichiers basé sur les options d'exécution.
        
        Returns:
            str: Suffixe comme "_sample" ou "_full"
        """
        if self.sample_mode:
            return "_sample"
        return "_full"
    
    def process_malicious_domains(self, show_progress: bool = True):
        """
        Traite le fichier down_domains_malicious.jsonl en streaming
        """
        print("=" * 80)
        print("ANALYSE DES DOMAINES MALICIEUX")
        print("=" * 80)
        
        # En mode échantillon, utiliser le fichier d'échantillon
        if self.sample_mode:
            malicious_file_to_use = OUTPUT_DIR.parent / "sample_data" / "down_domains_malicious_sample.jsonl"
            if not malicious_file_to_use.exists():
                print(f"✗ Erreur: Fichier d'échantillon {malicious_file_to_use} non trouvé")
                print("  Créez d'abord un échantillon avec: head -1000 analysis_results/down_domains_malicious.jsonl > sample_data/down_domains_malicious_sample.jsonl")
                return
        else:
            malicious_file_to_use = MALICIOUS_DOMAINS_FILE
        
        print(f"Lecture de {malicious_file_to_use}...\n")
        
        if not malicious_file_to_use.exists():
            print(f"✗ Erreur: Fichier {malicious_file_to_use} non trouvé")
            print("  Exécutez d'abord: python3 analyze_domains.py --dns-only")
            return
        
        stats_count = {
            'total_processed': 0,
            'with_creation_date': 0,
            'with_whois_bd': 0,
            'with_transition_date': 0,
            'with_discovery_time': 0,
            'with_metadata': 0,
            'with_dns_context': 0
        }
        
        # Estimer le nombre de lignes pour la barre de progression
        total_lines = None
        if HAS_TQDM and show_progress:
            try:
                with open(malicious_file_to_use, 'rb') as f:
                    total_lines = sum(1 for _ in f)
            except:
                pass
        
        iterator = open(malicious_file_to_use, 'r', encoding='utf-8')
        if HAS_TQDM and show_progress and total_lines:
            iterator = tqdm(iterator, total=total_lines, desc="Traitement", unit=" lignes")
        
        for line in iterator:
            line = line.strip()
            if not line:
                continue
            
            try:
                record = json.loads(line)
                stats_count['total_processed'] += 1
                
                if not isinstance(record, dict):
                    continue
                
                rd = record.get('rd', 'unknown')
                
                # Extraire les dates importantes
                whois_bd = record.get('whois_bd') or {}
                transition = record.get('transition') or {}
                takedown = record.get('takedown') or {}
                metadata = record.get('metadata') or {}
                dns_context = record.get('dns_context') or {}
                
                # Dates de base
                creation_date = None
                transition_date = None
                discovery_date = None
                transition_year = None
                
                # Date de création
                if whois_bd and isinstance(whois_bd, dict):
                    stats_count['with_whois_bd'] += 1
                    creation_date_str = whois_bd.get('cd', '')
                    creation_date = parse_date(creation_date_str) if creation_date_str else None
                    if creation_date:
                        stats_count['with_creation_date'] += 1
                
                # Date de transition (takedown)
                if transition and isinstance(transition, dict):
                    transition_date_str = transition.get('transition_date', '')
                    transition_date = parse_date(transition_date_str) if transition_date_str else None
                    if transition_date:
                        stats_count['with_transition_date'] += 1
                        transition_year = transition.get('year') or extract_year_from_date(transition_date_str)
                
                # Date de découverte
                discovery_time = record.get('discovery_time', '')
                if discovery_time:
                    stats_count['with_discovery_time'] += 1
                    if isinstance(discovery_time, int):
                        discovery_date = datetime.fromtimestamp(discovery_time)
                    elif isinstance(discovery_time, str):
                        discovery_date = parse_date(discovery_time)
                
                # Metadata
                if metadata and isinstance(metadata, dict):
                    stats_count['with_metadata'] += 1
                    src = metadata.get('src', 'unknown')
                    trg = metadata.get('trg', 'unknown')
                    tld = metadata.get('tld', 'unknown')
                else:
                    src = 'unknown'
                    trg = 'unknown'
                    tld = 'unknown'
                
                # DNS context
                if dns_context and isinstance(dns_context, dict):
                    stats_count['with_dns_context'] += 1
                
                # Takedown duration
                uptime_dur = None
                if takedown and isinstance(takedown, dict):
                    uptime_dur = takedown.get('uptime_dur')
                    if uptime_dur is not None:
                        duration_days = uptime_dur / 24
                
                # ===== ANALYSES =====
                
                # 2. & 3. Analyse par type d'attaque (source et target)
                if creation_date and transition_date:
                    delay_days = (transition_date - creation_date).total_seconds() / 86400
                    if 0 <= delay_days <= 18250:  # Max 50 ans
                        # Source
                        self.stats['attack_source_delays'].append({
                            'src': src,
                            'delay_days': delay_days,
                            'year': transition_year
                        })
                        # Target
                        self.stats['attack_target_delays'].append({
                            'trg': trg,
                            'delay_days': delay_days,
                            'year': transition_year
                        })
                        
                        if uptime_dur is not None:
                            # Source takedowns
                            self.stats['attack_source_takedowns'].append({
                                'src': src,
                                'duration_days': duration_days,
                                'year': transition_year
                            })
                            # Target takedowns
                            self.stats['attack_target_takedowns'].append({
                                'trg': trg,
                                'duration_days': duration_days,
                                'year': transition_year
                            })
                
                # 4. Analyse par registraire
                if whois_bd and isinstance(whois_bd, dict):
                    iana_id = whois_bd.get('iana_id', '')
                    if iana_id and creation_date and transition_date:
                        delay_days = (transition_date - creation_date).total_seconds() / 86400
                        if 0 <= delay_days <= 18250:
                            self.stats['registrar_delays'].append({
                                'iana_id': str(iana_id),
                                'delay_days': delay_days,
                                'year': transition_year
                            })
                            if uptime_dur is not None:
                                self.stats['registrar_takedowns'].append({
                                    'iana_id': str(iana_id),
                                    'duration_days': duration_days,
                                    'year': transition_year
                                })
                
                # 5. Analyse par TLD
                if tld != 'unknown' and creation_date and transition_date:
                    delay_days = (transition_date - creation_date).total_seconds() / 86400
                    if 0 <= delay_days <= 18250:
                        self.stats['tld_delays'].append({
                            'tld': tld,
                            'delay_days': delay_days,
                            'year': transition_year
                        })
                        if uptime_dur is not None:
                            self.stats['tld_takedowns'].append({
                                'tld': tld,
                                'duration_days': duration_days,
                                'year': transition_year
                            })
                
                # 6. Durée découverte → takedown
                if discovery_date and transition_date:
                    discovery_to_takedown_days = (transition_date - discovery_date).total_seconds() / 86400
                    if 0 <= discovery_to_takedown_days <= 3650:  # Max 10 ans
                        self.stats['discovery_to_takedown'].append({
                            'duration_days': discovery_to_takedown_days,
                            'year': transition_year
                        })
                
                # 7. Âge des domaines au takedown
                if creation_date and transition_date:
                    age_at_takedown_days = (transition_date - creation_date).total_seconds() / 86400
                    if 0 <= age_at_takedown_days <= 18250:
                        # Catégoriser l'âge
                        if age_at_takedown_days < 1:
                            age_category = "<1j"
                        elif age_at_takedown_days < 7:
                            age_category = "1-7j"
                        elif age_at_takedown_days < 30:
                            age_category = "7-30j"
                        elif age_at_takedown_days < 365:
                            age_category = "30j-1an"
                        else:
                            age_category = ">1an"
                        
                        self.stats['age_at_takedown'].append({
                            'age_days': age_at_takedown_days,
                            'year': transition_year,
                            'category': age_category
                        })
                
                # 8. Changements d'IP avant takedown
                if dns_context and isinstance(dns_context, dict):
                    before_entries = dns_context.get('before', [])
                    if before_entries:
                        # Collecter toutes les IPs avant transition
                        all_ips = set()
                        ip_changes = 0
                        previous_ips = set()
                        
                        for entry in before_entries:
                            if isinstance(entry, dict):
                                arec = entry.get('arec', [])
                                if arec:
                                    current_ips = set(str(ip) for ip in arec if ip and str(ip).strip())
                                    all_ips.update(current_ips)
                                    
                                    if previous_ips and current_ips != previous_ips:
                                        ip_changes += 1
                                    previous_ips = current_ips
                        
                        if len(all_ips) > 0:
                            self.stats['ip_changes'].append({
                                'change_count': ip_changes,
                                'unique_ips': len(all_ips),
                                'rd': rd
                            })
                
            except (json.JSONDecodeError, Exception) as e:
                if stats_count['total_processed'] % 10000 == 0:
                    print(f"  Warning: Erreur ligne {stats_count['total_processed']}: {e}")
                continue
        
        iterator.close()
        
        # Afficher les statistiques
        print("\n" + "=" * 80)
        print("RÉSUMÉ DU TRAITEMENT")
        print("=" * 80)
        print(f"✓ Domaines traités: {stats_count['total_processed']:,}")
        print(f"  • Avec date de création: {stats_count['with_creation_date']:,}")
        print(f"  • Avec date de transition: {stats_count['with_transition_date']:,}")
        print(f"  • Avec date de découverte: {stats_count['with_discovery_time']:,}")
        print(f"  • Avec metadata: {stats_count['with_metadata']:,}")
        print(f"  • Avec whois_bd: {stats_count['with_whois_bd']:,}")
        print(f"  • Avec dns_context: {stats_count['with_dns_context']:,}")
        print(f"\n📊 STATISTIQUES COLLECTÉES:")
        print(f"   • Délais par source: {len(self.stats['attack_source_delays']):,}")
        print(f"   • Takedowns par source: {len(self.stats['attack_source_takedowns']):,}")
        print(f"   • Délais par target: {len(self.stats['attack_target_delays']):,}")
        print(f"   • Takedowns par target: {len(self.stats['attack_target_takedowns']):,}")
        print(f"   • Délais par registraire: {len(self.stats['registrar_delays']):,}")
        print(f"   • Takedowns par registraire: {len(self.stats['registrar_takedowns']):,}")
        print(f"   • Délais par TLD: {len(self.stats['tld_delays']):,}")
        print(f"   • Takedowns par TLD: {len(self.stats['tld_takedowns']):,}")
        print(f"   • Durées découverte→takedown: {len(self.stats['discovery_to_takedown']):,}")
        print(f"   • Âges au takedown: {len(self.stats['age_at_takedown']):,}")
        print(f"   • Changements d'IP: {len(self.stats['ip_changes']):,}")
        print("=" * 80 + "\n")
    
    def generate_all_plots(self):
        """Génère tous les graphiques d'analyses"""
        if not HAS_PLOTTING:
            print("Graphiques désactivés (dépendances manquantes)")
            return
        
        print("\n=== Génération des graphiques ===")
        
        try:
            # 2. Analyse par type d'attaque (source)
            if self.stats['attack_source_delays']:
                self._plot_attack_source_analysis()
            
            # 3. Analyse par type d'attaque (target)
            if self.stats['attack_target_delays']:
                self._plot_attack_target_analysis()
            
            # 4. Analyse par registraire
            if self.stats['registrar_delays']:
                self._plot_registrar_analysis()
            
            # 5. Analyse par TLD
            if self.stats['tld_delays']:
                self._plot_tld_analysis()
            
            # 6. Durée découverte → takedown
            if self.stats['discovery_to_takedown']:
                self._plot_discovery_to_takedown()
            
            # 7. Âge des domaines au takedown
            if self.stats['age_at_takedown']:
                self._plot_age_at_takedown()
            
            # 8. Changements d'IP avant takedown
            if self.stats['ip_changes']:
                self._plot_ip_changes_analysis()
            
            print(f"Graphiques sauvegardés dans: {OUTPUT_DIR}")
            
        except Exception as e:
            print(f"Erreur lors de la génération des graphiques: {e}")
            import traceback
            traceback.print_exc()
    
    def _plot_attack_source_analysis(self):
        """2. Analyse par type d'attaque (source)"""
        print("  📊 Génération graphique analyse par source (metadata.src)...")
        
        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle('Analyse par type d\'attaque (Source)\nDomaines malicieux uniquement', 
                     fontsize=16, fontweight='bold')
        
        df_delays = pd.DataFrame(self.stats['attack_source_delays'])
        df_takedowns = pd.DataFrame(self.stats['attack_source_takedowns'])
        
        # 1. Délais création → takedown par source (Top 10)
        ax1 = axes[0, 0]
        if len(df_delays) > 0 and 'src' in df_delays.columns:
            top_sources = df_delays['src'].value_counts().head(10).index
            data_by_src = [df_delays[df_delays['src'] == src]['delay_days'].values 
                          for src in top_sources]
            
            if data_by_src:
                bp = ax1.boxplot(data_by_src, labels=top_sources, patch_artist=True, showfliers=False)
                for patch in bp['boxes']:
                    patch.set_facecolor('lightblue')
                ax1.set_xlabel('Source (Top 10)')
                ax1.set_ylabel('Délai création → takedown (jours)')
                ax1.set_title('Délais par source d\'attaque')
                ax1.tick_params(axis='x', rotation=45)
                ax1.grid(True, alpha=0.3, axis='y')
        
        # 2. Durées avant takedown par source (Top 10)
        ax2 = axes[0, 1]
        if len(df_takedowns) > 0 and 'src' in df_takedowns.columns:
            top_sources_tk = df_takedowns['src'].value_counts().head(10).index
            delays_by_src = [df_takedowns[df_takedowns['src'] == src]['duration_days'].mean() 
                            for src in top_sources_tk]
            
            if delays_by_src:
                ax2.barh(range(len(top_sources_tk)), delays_by_src, alpha=0.7, color='coral')
                ax2.set_yticks(range(len(top_sources_tk)))
                ax2.set_yticklabels(top_sources_tk)
                ax2.set_xlabel('Durée moyenne avant takedown (jours)')
                ax2.set_title('Durées moyennes par source (Top 10)')
                ax2.grid(True, alpha=0.3, axis='x')
        
        # 3. Distribution des sources
        ax3 = axes[1, 0]
        if len(df_delays) > 0 and 'src' in df_delays.columns:
            source_counts = df_delays['src'].value_counts().head(15)
            if len(source_counts) > 0:
                ax3.barh(range(len(source_counts)), source_counts.values, alpha=0.7, color='mediumseagreen')
                ax3.set_yticks(range(len(source_counts)))
                ax3.set_yticklabels(source_counts.index)
                ax3.set_xlabel('Nombre de domaines')
                ax3.set_title('Distribution des sources (Top 15)')
                ax3.grid(True, alpha=0.3, axis='x')
        
        # 4. Évolution temporelle par source (Top 5)
        ax4 = axes[1, 1]
        if len(df_delays) > 0 and 'src' in df_delays.columns and 'year' in df_delays.columns:
            top_sources_evo = df_delays['src'].value_counts().head(5).index
            for src in top_sources_evo:
                src_data = df_delays[df_delays['src'] == src]
                if 'year' in src_data.columns:
                    delays_by_year = src_data.groupby('year')['delay_days'].mean().sort_index()
                    if len(delays_by_year) > 0:
                        ax4.plot(delays_by_year.index, delays_by_year.values, 
                                marker='o', label=src, linewidth=2, markersize=6)
            
            ax4.set_xlabel('Année')
            ax4.set_ylabel('Délai moyen (jours)')
            ax4.set_title('Évolution délais moyens par source (Top 5)')
            ax4.legend(fontsize=8)
            ax4.grid(True, alpha=0.3)
        
        plt.tight_layout()
        suffix = self._get_filename_suffix()
        plt.savefig(OUTPUT_DIR / f'malicious_attack_source_analysis{suffix}.png', dpi=300, bbox_inches='tight')
        plt.close()
        import gc
        gc.collect()
        print(f"    ✓ malicious_attack_source_analysis{suffix}.png")
    
    def _plot_attack_target_analysis(self):
        """3. Analyse par type d'attaque (target)"""
        print("  📊 Génération graphique analyse par target (metadata.trg)...")
        
        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle('Analyse par type d\'attaque (Target)\nDomaines malicieux uniquement', 
                     fontsize=16, fontweight='bold')
        
        df_delays = pd.DataFrame(self.stats['attack_target_delays'])
        df_takedowns = pd.DataFrame(self.stats['attack_target_takedowns'])
        
        # 1. Délais création → takedown par target (Top 10)
        ax1 = axes[0, 0]
        if len(df_delays) > 0 and 'trg' in df_delays.columns:
            top_targets = df_delays['trg'].value_counts().head(10).index
            data_by_trg = [df_delays[df_delays['trg'] == trg]['delay_days'].values 
                          for trg in top_targets]
            
            if data_by_trg:
                bp = ax1.boxplot(data_by_trg, labels=top_targets, patch_artist=True, showfliers=False)
                for patch in bp['boxes']:
                    patch.set_facecolor('lightcoral')
                ax1.set_xlabel('Target (Top 10)')
                ax1.set_ylabel('Délai création → takedown (jours)')
                ax1.set_title('Délais par type d\'attaque (target)')
                ax1.tick_params(axis='x', rotation=45)
                ax1.grid(True, alpha=0.3, axis='y')
        
        # 2. Durées avant takedown par target (Top 10)
        ax2 = axes[0, 1]
        if len(df_takedowns) > 0 and 'trg' in df_takedowns.columns:
            top_targets_tk = df_takedowns['trg'].value_counts().head(10).index
            delays_by_trg = [df_takedowns[df_takedowns['trg'] == trg]['duration_days'].mean() 
                            for trg in top_targets_tk]
            
            if delays_by_trg:
                ax2.barh(range(len(top_targets_tk)), delays_by_trg, alpha=0.7, color='steelblue')
                ax2.set_yticks(range(len(top_targets_tk)))
                ax2.set_yticklabels(top_targets_tk)
                ax2.set_xlabel('Durée moyenne avant takedown (jours)')
                ax2.set_title('Durées moyennes par target (Top 10)')
                ax2.grid(True, alpha=0.3, axis='x')
        
        # 3. Distribution des targets
        ax3 = axes[1, 0]
        if len(df_delays) > 0 and 'trg' in df_delays.columns:
            target_counts = df_delays['trg'].value_counts().head(15)
            if len(target_counts) > 0:
                ax3.barh(range(len(target_counts)), target_counts.values, alpha=0.7, color='gold')
                ax3.set_yticks(range(len(target_counts)))
                ax3.set_yticklabels(target_counts.index)
                ax3.set_xlabel('Nombre de domaines')
                ax3.set_title('Distribution des targets (Top 15)')
                ax3.grid(True, alpha=0.3, axis='x')
        
        # 4. Évolution temporelle par target (Top 5)
        ax4 = axes[1, 1]
        if len(df_delays) > 0 and 'trg' in df_delays.columns and 'year' in df_delays.columns:
            top_targets_evo = df_delays['trg'].value_counts().head(5).index
            for trg in top_targets_evo:
                trg_data = df_delays[df_delays['trg'] == trg]
                if 'year' in trg_data.columns:
                    delays_by_year = trg_data.groupby('year')['delay_days'].mean().sort_index()
                    if len(delays_by_year) > 0:
                        ax4.plot(delays_by_year.index, delays_by_year.values, 
                                marker='o', label=trg, linewidth=2, markersize=6)
            
            ax4.set_xlabel('Année')
            ax4.set_ylabel('Délai moyen (jours)')
            ax4.set_title('Évolution délais moyens par target (Top 5)')
            ax4.legend(fontsize=8)
            ax4.grid(True, alpha=0.3)
        
        plt.tight_layout()
        suffix = self._get_filename_suffix()
        plt.savefig(OUTPUT_DIR / f'malicious_attack_target_analysis{suffix}.png', dpi=300, bbox_inches='tight')
        plt.close()
        import gc
        gc.collect()
        print(f"    ✓ malicious_attack_target_analysis{suffix}.png")
    
    def _plot_registrar_analysis(self):
        """4. Analyse par registraire (IANA ID)"""
        print("  📊 Génération graphique analyse par registraire (whois_bd.iana_id)...")
        
        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle('Analyse par registraire (IANA ID)\nDomaines malicieux uniquement', 
                     fontsize=16, fontweight='bold')
        
        df_delays = pd.DataFrame(self.stats['registrar_delays'])
        df_takedowns = pd.DataFrame(self.stats['registrar_takedowns'])
        
        # 1. Top registraires par nombre de domaines
        ax1 = axes[0, 0]
        if len(df_delays) > 0 and 'iana_id' in df_delays.columns:
            registrar_counts = df_delays['iana_id'].value_counts().head(15)
            if len(registrar_counts) > 0:
                ax1.barh(range(len(registrar_counts)), registrar_counts.values, 
                        alpha=0.7, color='steelblue')
                ax1.set_yticks(range(len(registrar_counts)))
                ax1.set_yticklabels([f"ID: {id}" for id in registrar_counts.index], fontsize=8)
                ax1.set_xlabel('Nombre de domaines malicieux')
                ax1.set_title('Top registraires par volume (Top 15)')
                ax1.grid(True, alpha=0.3, axis='x')
        
        # 2. Durées moyennes avant takedown par registraire (Top 15)
        ax2 = axes[0, 1]
        if len(df_takedowns) > 0 and 'iana_id' in df_takedowns.columns:
            top_registrars = df_takedowns['iana_id'].value_counts().head(15).index
            delays_by_registrar = []
            registrar_labels = []
            for reg_id in top_registrars:
                reg_data = df_takedowns[df_takedowns['iana_id'] == reg_id]
                if len(reg_data) > 0:
                    delays_by_registrar.append(reg_data['duration_days'].mean())
                    registrar_labels.append(f"ID: {reg_id}")
            
            if delays_by_registrar:
                ax2.barh(range(len(delays_by_registrar)), delays_by_registrar, 
                        alpha=0.7, color='coral')
                ax2.set_yticks(range(len(delays_by_registrar)))
                ax2.set_yticklabels(registrar_labels, fontsize=8)
                ax2.set_xlabel('Durée moyenne avant takedown (jours)')
                ax2.set_title('Durées moyennes par registraire (Top 15)')
                ax2.grid(True, alpha=0.3, axis='x')
        
        # 3. Délais création → takedown par registraire (Top 10)
        ax3 = axes[1, 0]
        if len(df_delays) > 0 and 'iana_id' in df_delays.columns:
            top_registrars_delay = df_delays['iana_id'].value_counts().head(10).index
            data_by_registrar = [df_delays[df_delays['iana_id'] == reg_id]['delay_days'].values 
                                for reg_id in top_registrars_delay]
            
            if data_by_registrar:
                bp = ax3.boxplot(data_by_registrar, 
                               labels=[f"ID:{id}" for id in top_registrars_delay], 
                               patch_artist=True, showfliers=False)
                for patch in bp['boxes']:
                    patch.set_facecolor('lightgreen')
                ax3.set_xlabel('Registraire (Top 10)')
                ax3.set_ylabel('Délai création → takedown (jours)')
                ax3.set_title('Distribution délais par registraire')
                ax3.tick_params(axis='x', rotation=45, labelsize=8)
                ax3.grid(True, alpha=0.3, axis='y')
        
        # 4. Scatter plot: Volume × Durée moyenne takedown
        ax4 = axes[1, 1]
        if len(df_takedowns) > 0 and 'iana_id' in df_takedowns.columns:
            registrar_stats = df_takedowns.groupby('iana_id').agg({
                'duration_days': ['mean', 'count']
            }).reset_index()
            registrar_stats.columns = ['iana_id', 'mean_duration', 'count']
            
            if len(registrar_stats) > 0:
                ax4.scatter(registrar_stats['count'], registrar_stats['mean_duration'], 
                           alpha=0.6, s=50, color='purple')
                ax4.set_xlabel('Nombre de domaines')
                ax4.set_ylabel('Durée moyenne avant takedown (jours)')
                ax4.set_title('Volume vs Durée moyenne takedown par registraire')
                ax4.grid(True, alpha=0.3)
                
                # Annoter les top registraires
                top_reg = registrar_stats.nlargest(5, 'count')
                for _, row in top_reg.iterrows():
                    ax4.annotate(f"ID:{row['iana_id']}", 
                               (row['count'], row['mean_duration']),
                               fontsize=7, alpha=0.7)
        
        plt.tight_layout()
        suffix = self._get_filename_suffix()
        plt.savefig(OUTPUT_DIR / f'malicious_registrar_analysis{suffix}.png', dpi=300, bbox_inches='tight')
        plt.close()
        import gc
        gc.collect()
        print(f"    ✓ malicious_registrar_analysis{suffix}.png")
    
    def _plot_tld_analysis(self):
        """5. Analyse par TLD"""
        print("  📊 Génération graphique analyse par TLD (metadata.tld)...")
        
        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle('Analyse par TLD\nDomaines malicieux uniquement', 
                     fontsize=16, fontweight='bold')
        
        df_delays = pd.DataFrame(self.stats['tld_delays'])
        df_takedowns = pd.DataFrame(self.stats['tld_takedowns'])
        
        # 1. Distribution des TLDs (Top 20)
        ax1 = axes[0, 0]
        if len(df_delays) > 0 and 'tld' in df_delays.columns:
            tld_counts = df_delays['tld'].value_counts().head(20)
            if len(tld_counts) > 0:
                ax1.bar(range(len(tld_counts)), tld_counts.values, 
                       alpha=0.7, color='steelblue', edgecolor='black')
                ax1.set_xticks(range(len(tld_counts)))
                ax1.set_xticklabels(tld_counts.index, rotation=45, ha='right')
                ax1.set_ylabel('Nombre de domaines')
                ax1.set_title('Distribution des TLDs (Top 20)')
                ax1.grid(True, alpha=0.3, axis='y')
                
                # Ajouter les valeurs sur les barres
                for i, v in enumerate(tld_counts.values):
                    ax1.text(i, v, f'{v:,}', ha='center', va='bottom', fontsize=8)
        
        # 2. Durées moyennes avant takedown par TLD (Top 15)
        ax2 = axes[0, 1]
        if len(df_takedowns) > 0 and 'tld' in df_takedowns.columns:
            top_tlds = df_takedowns['tld'].value_counts().head(15).index
            delays_by_tld = [df_takedowns[df_takedowns['tld'] == tld]['duration_days'].mean() 
                            for tld in top_tlds]
            
            if delays_by_tld:
                ax2.barh(range(len(top_tlds)), delays_by_tld, alpha=0.7, color='coral')
                ax2.set_yticks(range(len(top_tlds)))
                ax2.set_yticklabels(top_tlds)
                ax2.set_xlabel('Durée moyenne avant takedown (jours)')
                ax2.set_title('Durées moyennes par TLD (Top 15)')
                ax2.grid(True, alpha=0.3, axis='x')
        
        # 3. Délais création → takedown par TLD (Top 10)
        ax3 = axes[1, 0]
        if len(df_delays) > 0 and 'tld' in df_delays.columns:
            top_tlds_delay = df_delays['tld'].value_counts().head(10).index
            data_by_tld = [df_delays[df_delays['tld'] == tld]['delay_days'].values 
                          for tld in top_tlds_delay]
            
            if data_by_tld:
                bp = ax3.boxplot(data_by_tld, labels=top_tlds_delay, 
                               patch_artist=True, showfliers=False)
                for patch in bp['boxes']:
                    patch.set_facecolor('lightgreen')
                ax3.set_xlabel('TLD (Top 10)')
                ax3.set_ylabel('Délai création → takedown (jours)')
                ax3.set_title('Distribution délais par TLD')
                ax3.tick_params(axis='x', rotation=45)
                ax3.grid(True, alpha=0.3, axis='y')
        
        # 4. Évolution temporelle des TLDs (Top 5)
        ax4 = axes[1, 1]
        if len(df_delays) > 0 and 'tld' in df_delays.columns and 'year' in df_delays.columns:
            top_tlds_evo = df_delays['tld'].value_counts().head(5).index
            for tld in top_tlds_evo:
                tld_data = df_delays[df_delays['tld'] == tld]
                if 'year' in tld_data.columns:
                    counts_by_year = tld_data.groupby('year').size().sort_index()
                    if len(counts_by_year) > 0:
                        ax4.plot(counts_by_year.index, counts_by_year.values, 
                                marker='o', label=tld, linewidth=2, markersize=6)
            
            ax4.set_xlabel('Année')
            ax4.set_ylabel('Nombre de domaines')
            ax4.set_title('Évolution volume par TLD (Top 5)')
            ax4.legend(fontsize=8)
            ax4.grid(True, alpha=0.3)
        
        plt.tight_layout()
        suffix = self._get_filename_suffix()
        plt.savefig(OUTPUT_DIR / f'malicious_tld_analysis{suffix}.png', dpi=300, bbox_inches='tight')
        plt.close()
        import gc
        gc.collect()
        print(f"    ✓ malicious_tld_analysis{suffix}.png")
    
    def _plot_discovery_to_takedown(self):
        """6. Durée découverte → takedown"""
        print("  📊 Génération graphique durée découverte → takedown...")
        
        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle('Durée entre découverte et takedown\nDomaines malicieux uniquement', 
                     fontsize=16, fontweight='bold')
        
        df = pd.DataFrame(self.stats['discovery_to_takedown'])
        
        # 1. Histogramme de la distribution
        ax1 = axes[0, 0]
        if len(df) > 0 and 'duration_days' in df.columns:
            durations = df['duration_days'].values
            ax1.hist(durations, bins=50, edgecolor='black', alpha=0.7, color='steelblue')
            ax1.set_xlabel('Durée découverte → takedown (jours)')
            ax1.set_ylabel('Nombre de domaines')
            ax1.set_title('Distribution des durées')
            median = np.median(durations)
            ax1.axvline(median, color='r', linestyle='--', 
                       label=f'Médiane: {median:.1f}j')
            ax1.legend()
            ax1.grid(True, alpha=0.3, axis='y')
        
        # 2. Distribution logarithmique
        ax2 = axes[0, 1]
        if len(df) > 0 and 'duration_days' in df.columns:
            durations = df['duration_days'].values
            log_durations = np.log10(durations + 1)
            ax2.hist(log_durations, bins=50, edgecolor='black', alpha=0.7, color='coral')
            ax2.set_xlabel('log10(Durée + 1) jours')
            ax2.set_ylabel('Nombre de domaines')
            ax2.set_title('Distribution logarithmique')
            ax2.grid(True, alpha=0.3, axis='y')
        
        # 3. Évolution temporelle (par année)
        ax3 = axes[1, 0]
        if len(df) > 0 and 'year' in df.columns:
            durations_by_year = df.groupby('year')['duration_days'].agg(['mean', 'median']).sort_index()
            if len(durations_by_year) > 0:
                x = durations_by_year.index
                ax3.plot(x, durations_by_year['mean'], marker='o', label='Moyenne', 
                        linewidth=2, markersize=8, color='steelblue')
                ax3.plot(x, durations_by_year['median'], marker='s', label='Médiane', 
                        linewidth=2, markersize=8, color='coral')
                ax3.set_xlabel('Année')
                ax3.set_ylabel('Durée (jours)')
                ax3.set_title('Évolution vitesse de réaction (moyenne et médiane)')
                ax3.legend()
                ax3.grid(True, alpha=0.3)
        
        # 4. Box plot par année
        ax4 = axes[1, 1]
        if len(df) > 0 and 'year' in df.columns:
            years = sorted(df['year'].dropna().unique())
            if years:
                data_by_year = [df[df['year'] == y]['duration_days'].values for y in years]
                bp = ax4.boxplot(data_by_year, labels=years, patch_artist=True, showfliers=False)
                for patch in bp['boxes']:
                    patch.set_facecolor('lightgreen')
                ax4.set_xlabel('Année')
                ax4.set_ylabel('Durée découverte → takedown (jours)')
                ax4.set_title('Distribution par année')
                ax4.grid(True, alpha=0.3, axis='y')
        
        plt.tight_layout()
        suffix = self._get_filename_suffix()
        plt.savefig(OUTPUT_DIR / f'malicious_discovery_to_takedown{suffix}.png', dpi=300, bbox_inches='tight')
        plt.close()
        import gc
        gc.collect()
        print(f"    ✓ malicious_discovery_to_takedown{suffix}.png")
    
    def _plot_age_at_takedown(self):
        """7. Âge des domaines au takedown"""
        print("  📊 Génération graphique âge des domaines au takedown...")
        
        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle('Âge des domaines au moment du takedown\nDomaines malicieux uniquement', 
                     fontsize=16, fontweight='bold')
        
        df = pd.DataFrame(self.stats['age_at_takedown'])
        
        categories = ['<1j', '1-7j', '7-30j', '30j-1an', '>1an']
        
        # 1. Distribution de l'âge au takedown
        ax1 = axes[0, 0]
        if len(df) > 0 and 'age_days' in df.columns:
            ages = df['age_days'].values
            ax1.hist(ages, bins=100, edgecolor='black', alpha=0.7, color='steelblue', range=(0, 365))
            ax1.set_xlabel('Âge au takedown (jours)')
            ax1.set_ylabel('Nombre de domaines')
            ax1.set_title('Distribution de l\'âge au takedown (0-365 jours)')
            median = np.median(ages)
            ax1.axvline(median, color='r', linestyle='--', 
                       label=f'Médiane: {median:.1f}j')
            ax1.legend()
            ax1.grid(True, alpha=0.3, axis='y')
        
        # 2. Distribution par catégorie d'âge
        ax2 = axes[0, 1]
        if len(df) > 0 and 'category' in df.columns:
            age_counts = df['category'].value_counts()
            age_counts_ordered = [age_counts.get(cat, 0) for cat in categories if cat in age_counts.index]
            categories_present = [cat for cat in categories if cat in age_counts.index]
            
            if age_counts_ordered:
                ax2.bar(range(len(categories_present)), age_counts_ordered, 
                       alpha=0.7, color='coral', edgecolor='black')
                ax2.set_xticks(range(len(categories_present)))
                ax2.set_xticklabels(categories_present)
                ax2.set_ylabel('Nombre de domaines')
                ax2.set_title('Distribution par catégorie d\'âge')
                ax2.grid(True, alpha=0.3, axis='y')
                
                # Ajouter les valeurs sur les barres
                for i, v in enumerate(age_counts_ordered):
                    ax2.text(i, v, f'{v:,}', ha='center', va='bottom', fontsize=9)
        
        # 3. Box plot par catégorie d'âge
        ax3 = axes[1, 0]
        if len(df) > 0 and 'category' in df.columns:
            data_by_category = [df[df['category'] == cat]['age_days'].values 
                               for cat in categories if cat in df['category'].values]
            labels = [cat for cat in categories if cat in df['category'].values]
            
            if data_by_category:
                bp = ax3.boxplot(data_by_category, labels=labels, patch_artist=True, showfliers=False)
                for patch in bp['boxes']:
                    patch.set_facecolor('lightgreen')
                ax3.set_xlabel('Catégorie d\'âge')
                ax3.set_ylabel('Âge au takedown (jours)')
                ax3.set_title('Distribution par catégorie d\'âge')
                ax3.grid(True, alpha=0.3, axis='y')
        
        # 4. Évolution temporelle de l'âge moyen
        ax4 = axes[1, 1]
        if len(df) > 0 and 'year' in df.columns:
            age_by_year = df.groupby('year')['age_days'].agg(['mean', 'median']).sort_index()
            if len(age_by_year) > 0:
                x = age_by_year.index
                ax4.plot(x, age_by_year['mean'], marker='o', label='Moyenne', 
                        linewidth=2, markersize=8, color='steelblue')
                ax4.plot(x, age_by_year['median'], marker='s', label='Médiane', 
                        linewidth=2, markersize=8, color='coral')
                ax4.set_xlabel('Année')
                ax4.set_ylabel('Âge moyen au takedown (jours)')
                ax4.set_title('Évolution âge moyen au takedown')
                ax4.legend()
                ax4.grid(True, alpha=0.3)
        
        plt.tight_layout()
        suffix = self._get_filename_suffix()
        plt.savefig(OUTPUT_DIR / f'malicious_age_at_takedown{suffix}.png', dpi=300, bbox_inches='tight')
        plt.close()
        import gc
        gc.collect()
        print(f"    ✓ malicious_age_at_takedown{suffix}.png")
    
    def _plot_ip_changes_analysis(self):
        """8. Changements d'IP avant takedown"""
        print("  📊 Génération graphique changements d'IP avant takedown...")
        
        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle('Changements d\'IP avant takedown\nDomaines malicieux uniquement', 
                     fontsize=16, fontweight='bold')
        
        df = pd.DataFrame(self.stats['ip_changes'])
        
        # 1. Distribution du nombre de changements d'IP
        ax1 = axes[0, 0]
        if len(df) > 0 and 'change_count' in df.columns:
            change_counts = df['change_count'].value_counts().sort_index()
            if len(change_counts) > 0:
                ax1.bar(change_counts.index, change_counts.values, 
                       alpha=0.7, color='steelblue', edgecolor='black', width=0.8)
                ax1.set_xlabel('Nombre de changements d\'IP')
                ax1.set_ylabel('Nombre de domaines')
                ax1.set_title('Distribution des changements d\'IP')
                ax1.grid(True, alpha=0.3, axis='y')
        
        # 2. Distribution du nombre d'IPs uniques
        ax2 = axes[0, 1]
        if len(df) > 0 and 'unique_ips' in df.columns:
            unique_ips_counts = df['unique_ips'].value_counts().sort_index().head(20)
            if len(unique_ips_counts) > 0:
                ax2.bar(range(len(unique_ips_counts)), unique_ips_counts.values, 
                       alpha=0.7, color='coral', edgecolor='black')
                ax2.set_xticks(range(len(unique_ips_counts)))
                ax2.set_xticklabels([str(x) for x in unique_ips_counts.index], rotation=45, ha='right')
                ax2.set_xlabel('Nombre d\'IPs uniques utilisées')
                ax2.set_ylabel('Nombre de domaines')
                ax2.set_title('Distribution du nombre d\'IPs uniques (0-20)')
                ax2.grid(True, alpha=0.3, axis='y')
        
        # 3. Proportion domaines avec/sans changement d'IP
        ax3 = axes[1, 0]
        if len(df) > 0 and 'change_count' in df.columns:
            with_changes = (df['change_count'] > 0).sum()
            without_changes = (df['change_count'] == 0).sum()
            
            if with_changes + without_changes > 0:
                ax3.pie([with_changes, without_changes],
                       labels=['Avec changements', 'Sans changement'],
                       autopct='%1.1f%%', startangle=90,
                       colors=['coral', 'lightblue'])
                ax3.set_title('Proportion domaines avec changements d\'IP')
        
        # 4. Statistiques des changements
        ax4 = axes[1, 1]
        if len(df) > 0:
            stats_text = f"""
Statistiques changements d'IP:

Total domaines analysés: {len(df):,}

Changements d'IP:
  • Moyenne: {df['change_count'].mean():.2f}
  • Médiane: {df['change_count'].median():.0f}
  • Max: {df['change_count'].max():.0f}
  • Avec changements: {(df['change_count'] > 0).sum():,}
  • Sans changement: {(df['change_count'] == 0).sum():,}

IPs uniques:
  • Moyenne: {df['unique_ips'].mean():.2f}
  • Médiane: {df['unique_ips'].median():.0f}
  • Max: {df['unique_ips'].max():.0f}
            """
            ax4.text(0.1, 0.5, stats_text, fontsize=11, 
                    verticalalignment='center', family='monospace')
            ax4.axis('off')
        
        plt.tight_layout()
        suffix = self._get_filename_suffix()
        plt.savefig(OUTPUT_DIR / f'malicious_ip_changes{suffix}.png', dpi=300, bbox_inches='tight')
        plt.close()
        import gc
        gc.collect()
        print(f"    ✓ malicious_ip_changes{suffix}.png")
    
    def run_analysis(self, show_progress: bool = True):
        """Exécute l'analyse complète"""
        print("=" * 80)
        print("ANALYSE DES DOMAINES MALICIEUX")
        print("=" * 80)
        
        # Traiter les données
        self.process_malicious_domains(show_progress=show_progress)
        
        # Générer les visualisations
        if show_progress:
            print("\nGénération des graphiques...")
        self.generate_all_plots()
        
        print("\n" + "=" * 80)
        print("ANALYSE TERMINÉE")
        print("=" * 80)
        print(f"Résultats sauvegardés dans: {OUTPUT_DIR}")


def main():
    """Point d'entrée principal"""
    import sys
    
    # Vérifier si mode échantillon activé
    sample_mode = '--sample' in sys.argv or '-s' in sys.argv
    
    if sample_mode:
        print("=" * 80)
        print("MODE ÉCHANTILLON ACTIVÉ")
        print("Utilisation des fichiers dans sample_data/")
        print("=" * 80)
        print()
    
    analyzer = MaliciousDomainAnalyzer(sample_mode=sample_mode)
    analyzer.run_analysis()


if __name__ == "__main__":
    main()
