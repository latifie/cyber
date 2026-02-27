"""
Analyse des hypothèses sur le fichier malicious_domains_takedown_whois_sample.jsonl
Analyse spécifique des 96 domaines malicieux extraits avec takedown WHOIS.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from collections import Counter, defaultdict
from typing import Dict, List, Optional
import statistics

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns

# Chemins
DATA_DIR = Path(__file__).parent
RESULTS_DIR = DATA_DIR / "analysis_results"
GRAPHS_DIR = RESULTS_DIR / "graphs_sample"
GRAPHS_DIR.mkdir(parents=True, exist_ok=True)

# Style
sns.set_style("whitegrid")
plt.rcParams['figure.figsize'] = (12, 6)


def parse_datetime(dt_str: str) -> Optional[datetime]:
    """Parse une date ISO avec gestion des erreurs - uniformise les timezones."""
    if not dt_str:
        return None
    try:
        # Format ISO : 2025-01-01T00:30:02
        if 'T' in dt_str:
            dt = datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
            # Si pas de timezone, ajouter UTC
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        # Format date simple : 2024-12-29
        return datetime.strptime(dt_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        return None


def calculate_aging_days(discovery_time: str, creation_date: str) -> Optional[float]:
    """Calcule le vieillissement en jours."""
    dt_disc = parse_datetime(discovery_time)
    dt_create = parse_datetime(creation_date)
    
    if not dt_disc or not dt_create:
        return None
    
    delta = dt_disc - dt_create
    days = delta.total_seconds() / 86400
    
    # Filtrer valeurs aberrantes
    if days < 0 or days > 18250:  # > 50 ans
        return None
    
    return days


def calculate_takedown_hours(discovery_time: str, takedown_time: str) -> Optional[float]:
    """Calcule le délai de takedown en heures."""
    dt_disc = parse_datetime(discovery_time)
    dt_takedown = parse_datetime(takedown_time)
    
    if not dt_disc or not dt_takedown:
        return None
    
    delta = dt_takedown - dt_disc
    hours = delta.total_seconds() / 3600
    
    # Filtrer valeurs aberrantes
    if hours < 0 or hours > 87600:  # > 10 ans
        return None
    
    return hours


def load_malicious_domains(filepath: Path) -> List[Dict]:
    """Charge les domaines malicieux depuis le JSONL."""
    domains = []
    with filepath.open('r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                domains.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return domains


def analyze_domains(filepath: Path) -> Dict:
    """Analyse principale des 3 hypothèses."""
    print(f"[+] Chargement: {filepath}")
    domains = load_malicious_domains(filepath)
    print(f"[+] Domaines chargés: {len(domains)}")
    
    # Structures de données
    aging_days = []
    sources = []
    targets = []
    tlds = []
    takedown_hours = []
    takedown_by_reason = defaultdict(list)
    
    # Analyse de chaque domaine
    for rec in domains:
        # === HYPOTHÈSE 1: VIEILLISSEMENT ===
        discovery_time = rec.get('discovery_time')
        
        # Trouver la date de création (cd) depuis whois_bd ou uptime
        creation_date = None
        if 'whois_bd' in rec and rec['whois_bd']:
            creation_date = rec['whois_bd'].get('cd')
        
        # Si pas trouvé, chercher dans uptime
        if not creation_date and 'uptime' in rec:
            for entry in rec['uptime']:
                if entry.get('type') == 'whois' and entry.get('cd'):
                    creation_date = entry['cd']
                    break
        
        if discovery_time and creation_date:
            aging = calculate_aging_days(discovery_time, creation_date)
            if aging is not None:
                aging_days.append(aging)
        
        # === HYPOTHÈSE 2: PATTERNS D'ATTAQUE ===
        metadata = rec.get('metadata', {})
        if metadata:
            src = metadata.get('src')
            trg = metadata.get('trg')
            tld = metadata.get('tld')
            
            if src:
                sources.append(src)
            if trg:
                targets.append(trg)
            if tld:
                tlds.append(tld)
        
        # === HYPOTHÈSE 3: DÉLAI TAKEDOWN ===
        takedown = rec.get('takedown', {})
        if takedown and 'takedowns' in takedown:
            takedowns_list = takedown['takedowns']
            if takedowns_list and len(takedowns_list) > 0:
                # Premier takedown
                first_takedown = takedowns_list[0]
                takedown_dt = first_takedown.get('dt')
                takedown_type = first_takedown.get('type', 'unknown')
                
                if discovery_time and takedown_dt:
                    hours = calculate_takedown_hours(discovery_time, takedown_dt)
                    if hours is not None:
                        takedown_hours.append(hours)
                        takedown_by_reason[takedown_type].append(hours)
    
    # Calculs statistiques
    stats = {
        'total': len(domains),
        'aging': {
            'count': len(aging_days),
            'mean': statistics.mean(aging_days) if aging_days else 0,
            'median': statistics.median(aging_days) if aging_days else 0,
            'min': min(aging_days) if aging_days else 0,
            'max': max(aging_days) if aging_days else 0,
            'q1': statistics.quantiles(aging_days, n=4)[0] if len(aging_days) >= 2 else 0,
            'q3': statistics.quantiles(aging_days, n=4)[2] if len(aging_days) >= 2 else 0,
            'values': aging_days
        },
        'sources': Counter(sources),
        'targets': Counter(targets),
        'tlds': Counter(tlds),
        'takedown': {
            'count': len(takedown_hours),
            'mean': statistics.mean(takedown_hours) if takedown_hours else 0,
            'median': statistics.median(takedown_hours) if takedown_hours else 0,
            'min': min(takedown_hours) if takedown_hours else 0,
            'max': max(takedown_hours) if takedown_hours else 0,
            'values': takedown_hours,
            'by_reason': {k: {
                'count': len(v),
                'median': statistics.median(v) if v else 0,
                'mean': statistics.mean(v) if v else 0
            } for k, v in takedown_by_reason.items()}
        }
    }
    
    return stats


def plot_aging_analysis(stats: Dict) -> None:
    """Graphiques pour l'hypothèse 1: Vieillissement."""
    aging_days = stats['aging']['values']
    
    if not aging_days:
        print("[!] Pas de données de vieillissement")
        return
    
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle('Hypothèse 1: Vieillissement des domaines malicieux', fontsize=16, fontweight='bold')
    
    # 1. Histogramme
    ax = axes[0, 0]
    ax.hist(aging_days, bins=30, edgecolor='black', alpha=0.7, color='crimson')
    ax.axvline(stats['aging']['median'], color='blue', linestyle='--', linewidth=2, label=f'Médiane: {stats["aging"]["median"]:.1f}j')
    ax.axvline(stats['aging']['mean'], color='green', linestyle='--', linewidth=2, label=f'Moyenne: {stats["aging"]["mean"]:.1f}j')
    ax.set_xlabel('Jours entre création et découverte')
    ax.set_ylabel('Nombre de domaines')
    ax.set_title('Distribution du vieillissement')
    ax.legend()
    ax.grid(True, alpha=0.3)
    
    # 2. Box plot
    ax = axes[0, 1]
    bp = ax.boxplot([aging_days], vert=True, patch_artist=True, widths=0.5)
    bp['boxes'][0].set_facecolor('lightcoral')
    ax.set_ylabel('Jours')
    ax.set_title('Statistiques descriptives')
    ax.set_xticklabels(['Vieillissement'])
    ax.grid(True, alpha=0.3, axis='y')
    
    # 3. Distribution log
    ax = axes[1, 0]
    aging_nonzero = [d for d in aging_days if d > 0]
    if aging_nonzero:
        ax.hist(aging_nonzero, bins=30, edgecolor='black', alpha=0.7, color='orange')
        ax.set_yscale('log')
        ax.set_xlabel('Jours entre création et découverte')
        ax.set_ylabel('Nombre de domaines (échelle log)')
        ax.set_title('Distribution logarithmique')
        ax.grid(True, alpha=0.3)
    
    # 4. Courbe cumulative
    ax = axes[1, 1]
    sorted_aging = sorted(aging_days)
    cumulative = [(i+1)/len(sorted_aging)*100 for i in range(len(sorted_aging))]
    ax.plot(sorted_aging, cumulative, linewidth=2, color='darkred')
    ax.axhline(50, color='blue', linestyle='--', alpha=0.5, label='Médiane')
    ax.axhline(75, color='green', linestyle='--', alpha=0.5, label='Q3')
    ax.set_xlabel('Jours')
    ax.set_ylabel('Pourcentage cumulé (%)')
    ax.set_title('Distribution cumulative')
    ax.legend()
    ax.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(GRAPHS_DIR / 'hypothesis1_aging.png', dpi=300, bbox_inches='tight')
    print(f"[✓] Graphique sauvegardé: hypothesis1_aging.png")
    plt.close()


def plot_attack_patterns(stats: Dict) -> None:
    """Graphiques pour l'hypothèse 2: Patterns d'attaque."""
    fig, axes = plt.subplots(1, 3, figsize=(18, 6))
    fig.suptitle('Hypothèse 2: Patterns d\'attaque', fontsize=16, fontweight='bold')
    
    # 1. Top sources
    ax = axes[0]
    top_sources = stats['sources'].most_common(10)
    if top_sources:
        sources, counts = zip(*top_sources)
        ax.barh(range(len(sources)), counts, color='steelblue', edgecolor='black')
        ax.set_yticks(range(len(sources)))
        ax.set_yticklabels(sources)
        ax.set_xlabel('Nombre de domaines')
        ax.set_title('Top 10 Sources')
        ax.invert_yaxis()
        ax.grid(True, alpha=0.3, axis='x')
    
    # 2. Top cibles
    ax = axes[1]
    top_targets = stats['targets'].most_common(15)
    if top_targets:
        targets, counts = zip(*top_targets)
        ax.barh(range(len(targets)), counts, color='coral', edgecolor='black')
        ax.set_yticks(range(len(targets)))
        ax.set_yticklabels(targets)
        ax.set_xlabel('Nombre de domaines')
        ax.set_title('Top 15 Cibles')
        ax.invert_yaxis()
        ax.grid(True, alpha=0.3, axis='x')
    
    # 3. Top TLDs
    ax = axes[2]
    top_tlds = stats['tlds'].most_common(15)
    if top_tlds:
        tlds, counts = zip(*top_tlds)
        colors = plt.cm.Set3(range(len(tlds)))
        ax.bar(range(len(tlds)), counts, color=colors, edgecolor='black')
        ax.set_xticks(range(len(tlds)))
        ax.set_xticklabels(tlds, rotation=45, ha='right')
        ax.set_ylabel('Nombre de domaines')
        ax.set_title('Top 15 TLDs')
        ax.grid(True, alpha=0.3, axis='y')
    
    plt.tight_layout()
    plt.savefig(GRAPHS_DIR / 'hypothesis2_patterns.png', dpi=300, bbox_inches='tight')
    print(f"[✓] Graphique sauvegardé: hypothesis2_patterns.png")
    plt.close()


def plot_takedown_analysis(stats: Dict) -> None:
    """Graphiques pour l'hypothèse 3: Délai de takedown."""
    takedown_hours = stats['takedown']['values']
    
    if not takedown_hours:
        print("[!] Pas de données de takedown")
        return
    
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle('Hypothèse 3: Délai de takedown', fontsize=16, fontweight='bold')
    
    # 1. Histogramme (heures)
    ax = axes[0, 0]
    ax.hist(takedown_hours, bins=30, edgecolor='black', alpha=0.7, color='forestgreen')
    ax.axvline(stats['takedown']['median'], color='blue', linestyle='--', linewidth=2, 
               label=f'Médiane: {stats["takedown"]["median"]:.1f}h ({stats["takedown"]["median"]/24:.1f}j)')
    ax.set_xlabel('Heures entre découverte et takedown')
    ax.set_ylabel('Nombre de domaines')
    ax.set_title('Distribution du délai de takedown')
    ax.legend()
    ax.grid(True, alpha=0.3)
    
    # 2. Par type de takedown
    ax = axes[0, 1]
    takedown_by_reason = stats['takedown']['by_reason']
    if takedown_by_reason:
        reasons = list(takedown_by_reason.keys())
        medians = [takedown_by_reason[r]['median'] for r in reasons]
        counts = [takedown_by_reason[r]['count'] for r in reasons]
        
        colors = ['red' if r == 'whois' else 'orange' if r == 'dns' else 'gray' for r in reasons]
        bars = ax.bar(range(len(reasons)), medians, color=colors, edgecolor='black', alpha=0.7)
        ax.set_xticks(range(len(reasons)))
        ax.set_xticklabels(reasons, rotation=45, ha='right')
        ax.set_ylabel('Médiane (heures)')
        ax.set_title('Médiane par type de takedown')
        ax.grid(True, alpha=0.3, axis='y')
        
        # Ajouter le nombre de domaines au-dessus des barres
        for i, (bar, count) in enumerate(zip(bars, counts)):
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                   f'n={count}', ha='center', va='bottom', fontsize=9)
    
    # 3. Distribution jours
    ax = axes[1, 0]
    takedown_days = [h/24 for h in takedown_hours]
    ax.hist(takedown_days, bins=30, edgecolor='black', alpha=0.7, color='teal')
    ax.axvline(stats['takedown']['median']/24, color='blue', linestyle='--', linewidth=2,
               label=f'Médiane: {stats["takedown"]["median"]/24:.1f}j')
    ax.set_xlabel('Jours entre découverte et takedown')
    ax.set_ylabel('Nombre de domaines')
    ax.set_title('Distribution en jours')
    ax.legend()
    ax.grid(True, alpha=0.3)
    
    # 4. Courbe cumulative
    ax = axes[1, 1]
    sorted_hours = sorted(takedown_hours)
    cumulative = [(i+1)/len(sorted_hours)*100 for i in range(len(sorted_hours))]
    ax.plot(sorted_hours, cumulative, linewidth=2, color='darkgreen')
    ax.axhline(50, color='blue', linestyle='--', alpha=0.5, label='Médiane')
    ax.axhline(75, color='orange', linestyle='--', alpha=0.5, label='Q3')
    ax.set_xlabel('Heures')
    ax.set_ylabel('Pourcentage cumulé (%)')
    ax.set_title('Distribution cumulative')
    ax.legend()
    ax.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(GRAPHS_DIR / 'hypothesis3_takedown.png', dpi=300, bbox_inches='tight')
    print(f"[✓] Graphique sauvegardé: hypothesis3_takedown.png")
    plt.close()


def generate_report(stats: Dict, filepath: Path) -> None:
    """Génère un rapport texte complet."""
    report_path = GRAPHS_DIR / 'analysis_report_sample.txt'
    
    with report_path.open('w', encoding='utf-8') as f:
        f.write("="*80 + "\n")
        f.write("RAPPORT D'ANALYSE - DOMAINES MALICIEUX (SAMPLE)\n")
        f.write("="*80 + "\n\n")
        
        f.write(f"Fichier analysé: {filepath.name}\n")
        f.write(f"Total de domaines: {stats['total']}\n\n")
        
        # Hypothèse 1
        f.write("HYPOTHÈSE 1: VIEILLISSEMENT DES DOMAINES\n")
        f.write("-"*80 + "\n")
        f.write(f"Domaines avec données: {stats['aging']['count']}/{stats['total']}\n")
        f.write(f"Moyenne: {stats['aging']['mean']:.1f} jours\n")
        f.write(f"Médiane: {stats['aging']['median']:.1f} jours\n")
        f.write(f"Q1-Q3: {stats['aging']['q1']:.1f} - {stats['aging']['q3']:.1f} jours\n")
        f.write(f"Min-Max: {stats['aging']['min']:.1f} - {stats['aging']['max']:.1f} jours\n\n")
        
        f.write("INTERPRÉTATION:\n")
        median_days = stats['aging']['median']
        if median_days <= 5:
            f.write(f"✓ {median_days:.1f} jours médiane = utilisation IMMÉDIATE après création\n")
            f.write("✓ Confirme stratégie 'hit-and-run' sans vieillissement intentionnel\n")
        elif median_days <= 30:
            f.write(f"⚠ {median_days:.1f} jours médiane = vieillissement court\n")
        else:
            f.write(f"⚠ {median_days:.1f} jours médiane = vieillissement significatif\n")
        
        q75_pct = sum(1 for d in stats['aging']['values'] if d <= 5) / len(stats['aging']['values']) * 100
        f.write(f"✓ {q75_pct:.0f}% des domaines utilisés en ≤5 jours\n\n")
        
        # Hypothèse 2
        f.write("HYPOTHÈSE 2: PATTERNS D'ATTAQUE\n")
        f.write("-"*80 + "\n")
        
        f.write("\nTOP 10 SOURCES:\n")
        for src, count in stats['sources'].most_common(10):
            pct = count / stats['total'] * 100
            f.write(f"  {src}: {count} ({pct:.1f}%)\n")
        
        f.write("\nTOP 15 CIBLES:\n")
        for trg, count in stats['targets'].most_common(15):
            pct = count / stats['total'] * 100
            f.write(f"  {trg}: {count} ({pct:.1f}%)\n")
        
        f.write("\nTOP 15 TLDs:\n")
        for tld, count in stats['tlds'].most_common(15):
            pct = count / stats['total'] * 100
            f.write(f"  .{tld}: {count} ({pct:.1f}%)\n")
        
        f.write("\nINTERPRÉTATION:\n")
        top_target = stats['targets'].most_common(1)[0] if stats['targets'] else ('N/A', 0)
        top_tld = stats['tlds'].most_common(1)[0] if stats['tlds'] else ('N/A', 0)
        f.write(f"✓ Cible dominante: {top_target[0]} ({top_target[1]} domaines, {top_target[1]/stats['total']*100:.1f}%)\n")
        f.write(f"✓ TLD le plus abusé: .{top_tld[0]} ({top_tld[1]} domaines, {top_tld[1]/stats['total']*100:.1f}%)\n\n")
        
        # Hypothèse 3
        f.write("HYPOTHÈSE 3: DÉLAI DE TAKEDOWN\n")
        f.write("-"*80 + "\n")
        f.write(f"Domaines avec données: {stats['takedown']['count']}/{stats['total']}\n")
        f.write(f"Moyenne: {stats['takedown']['mean']:.1f}h ({stats['takedown']['mean']/24:.1f}j)\n")
        f.write(f"Médiane: {stats['takedown']['median']:.1f}h ({stats['takedown']['median']/24:.1f}j)\n")
        f.write(f"Min-Max: {stats['takedown']['min']:.1f}h - {stats['takedown']['max']:.1f}h\n\n")
        
        f.write("PAR TYPE DE TAKEDOWN:\n")
        for reason, data in sorted(stats['takedown']['by_reason'].items(), 
                                   key=lambda x: x[1]['median']):
            f.write(f"  {reason.upper()}: {data['count']} domaines, "
                   f"médiane {data['median']:.1f}h ({data['median']/24:.1f}j)\n")
        
        f.write("\nINTERPRÉTATION:\n")
        median_hours = stats['takedown']['median']
        f.write(f"✓ Délai médian: {median_hours:.1f}h ({median_hours/24:.1f}j)\n")
        if median_hours < 24:
            f.write("✓ Réponse RAPIDE (<24h) des mécanismes de takedown\n")
        elif median_hours < 72:
            f.write("✓ Réponse dans les 3 jours - efficace\n")
        else:
            f.write("⚠ Délai >3 jours - fenêtre d'exploitation significative\n")
        
        f.write("\n" + "="*80 + "\n")
    
    print(f"[✓] Rapport sauvegardé: {report_path}")


def main():
    """Point d'entrée principal."""
    # Trouver le fichier le plus récent
    malicious_files = list(RESULTS_DIR.glob('malicious_domains_takedown_whois_sample_*.jsonl'))
    
    if not malicious_files:
        print("[!] Aucun fichier malicious_domains_takedown_whois_sample_*.jsonl trouvé")
        print(f"[!] Recherche dans: {RESULTS_DIR}")
        return
    
    # Prendre le plus récent
    filepath = sorted(malicious_files)[-1]
    
    print("="*80)
    print("ANALYSE DES HYPOTHÈSES - DOMAINES MALICIEUX")
    print("="*80)
    print(f"Fichier: {filepath.name}\n")
    
    # Analyse
    stats = analyze_domains(filepath)
    
    # Génération des graphiques
    print("\n[+] Génération des graphiques...")
    plot_aging_analysis(stats)
    plot_attack_patterns(stats)
    plot_takedown_analysis(stats)
    
    # Génération du rapport
    print("\n[+] Génération du rapport...")
    generate_report(stats, filepath)
    
    print("\n" + "="*80)
    print("RÉSUMÉ DES RÉSULTATS")
    print("="*80)
    print(f"Total domaines: {stats['total']}")
    print(f"\nHypothèse 1 - Vieillissement:")
    print(f"  Médiane: {stats['aging']['median']:.1f} jours")
    print(f"  Moyenne: {stats['aging']['mean']:.1f} jours")
    print(f"\nHypothèse 2 - Patterns:")
    if stats['targets']:
        top_target = stats['targets'].most_common(1)[0]
        print(f"  Top cible: {top_target[0]} ({top_target[1]} domaines)")
    if stats['tlds']:
        top_tld = stats['tlds'].most_common(1)[0]
        print(f"  Top TLD: .{top_tld[0]} ({top_tld[1]} domaines)")
    print(f"\nHypothèse 3 - Takedown:")
    print(f"  Médiane: {stats['takedown']['median']:.1f}h ({stats['takedown']['median']/24:.1f}j)")
    print(f"  Moyenne: {stats['takedown']['mean']:.1f}h ({stats['takedown']['mean']/24:.1f}j)")
    print("\n" + "="*80)
    print(f"Résultats dans: {GRAPHS_DIR}/")
    print("="*80)


if __name__ == "__main__":
    main()