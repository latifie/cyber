import json
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict
import statistics

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

# Chemins
DATA_DIR = Path(__file__).parent
RESULTS_DIR = DATA_DIR / "analysis_results"
GRAPHS_DIR = RESULTS_DIR / "graphs_advanced"
GRAPHS_DIR.mkdir(parents=True, exist_ok=True)

# Définition du style
sns.set_style("whitegrid")
plt.rcParams['figure.figsize'] = (12, 6)
plt.rcParams['font.size'] = 12

def parse_datetime(dt_str: str):
    """Parse une date ISO avec gestion des erreurs - uniformise les timezones."""
    if not dt_str:
        return None
    try:
        if 'T' in dt_str:
            dt = datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        return datetime.strptime(dt_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        return None

def main():
    # 1. Chargement du fichier existant (celui qui a des WHOIS)
    malicious_files = list(RESULTS_DIR.glob('malicious_domains_takedown_whois_sample_*.jsonl'))
    if not malicious_files:
        print("[!] Aucun fichier trouvé.")
        return
    
    filepath = sorted(malicious_files)[-1]
    print(f"[+] Analyse de: {filepath.name}")

    # Structures
    data_points = []
    
    with filepath.open('r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line: continue
            
            try:
                rec = json.loads(line)
            except:
                continue

            # Extraction
            discovery = rec.get("discovery_time")
            takedown_dur = None
            takedown_reason = None
            
            takedown_block = rec.get("takedown", {})
            if takedown_block:
                takedown_dur = takedown_block.get("uptime_dur")
                takedown_reason = takedown_block.get("takedown_reason")
                
            metadata = rec.get("metadata", {})
            tld = metadata.get("tld", "unknown")
            trg = metadata.get("trg", "unknown") # Nouvelle extraction cible
            
            # Rechercher date de création (cd) et de mise à jour (ud)
            creation_date = None
            update_date = None
            if rec.get("whois_bd"):
                creation_date = rec["whois_bd"].get("cd")
                update_date = rec["whois_bd"].get("ud")
            elif rec.get("uptime"):
                for entry in rec["uptime"]:
                    if entry.get("type") == "whois":
                        if entry.get("cd") and not creation_date:
                            creation_date = entry.get("cd")
                        if entry.get("ud") and not update_date:
                            update_date = entry.get("ud")
                        if creation_date and update_date:
                            break
                        
            # Recherche Re-up (NXDOMAIN -> NOERROR) et Comptage d'IPs
            has_reup = False
            ips = set()
            if rec.get("uptime"):
                dns_statuses = []
                for u in rec["uptime"]:
                    if u.get("type") == "dns" and u.get("dns_status"):
                        dns_statuses.append(u.get("dns_status"))
                    if u.get("arec"):
                        for ip in u["arec"]:
                            ips.add(ip)
                
                # Simple heuristique: Mettre à True s'il y a un NOERROR *après* un NXDOMAIN
                nx_seen = False
                for status in dns_statuses:
                    if status == "NXDOMAIN":
                        nx_seen = True
                    elif status == "NOERROR" and nx_seen:
                        has_reup = True
                        break
            
            unique_ips_count = len(ips)

            # Extractions Morphologiques (Hypothèse 8)
            domain_name = rec.get("rd", "").split(".")[0] # On enlève le TLD pour analyser le nom lui-même
            domain_length = len(domain_name)
            dash_count = domain_name.count("-")
            digit_count = sum(c.isdigit() for c in domain_name)

            # Calculs finaux si on a creation et discovery
            if creation_date and discovery and takedown_dur is not None:
                dt_create = parse_datetime(creation_date)
                dt_disc = parse_datetime(discovery)
                dt_update = parse_datetime(update_date) if update_date else None
                
                if dt_create and dt_disc:
                    aging_days = (dt_disc - dt_create).total_seconds() / 86400.0
                    
                    # Drop Catching H6 : Si la mise à jour (ud) est intervenue LONGTEMPS après la création mais JUSTE AVANT l'attaque
                    drop_catching_days = None
                    if dt_update and dt_update > dt_create:
                        drop_catching_days = (dt_disc - dt_update).total_seconds() / 86400.0
                        
                    if 0 <= aging_days <= 18250: # max 50 ans
                        
                        # --- CALCUL DU SCORE DE SOPHISTICATION (Hypothèse 10) ---
                        score = 0
                        
                        # 1. Âge (Max 25 points) - Un domaine vieilli volontairement demande des ressources
                        if aging_days > 60: score += 25
                        elif aging_days > 30: score += 15
                        elif aging_days > 7: score += 5
                        
                        # 2. TLD Premium vs Gratuit (Max 15 points)
                        premium_tlds = {"com", "org", "net", "co", "us", "uk", "fr", "de", "ca", "io"}
                        free_tlds = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "pw", "site", "online", "click", "vip", "win", "bid"}
                        if tld in premium_tlds:
                            score += 15
                        elif tld not in free_tlds:
                            score += 5
                            
                        # 3. Morphologie (Dissimulation vs Phishing de masse) (Max 20 points)
                        # Un nom court sans tirets ressemble plus à un service légitime (C&C, dropzone)
                        if domain_length < 15: score += 10
                        if dash_count < 2: score += 5
                        if digit_count == 0: score += 5
                            
                        # 4. Infrastructure (IP multiples / Fast Flux) (Max 20 points)
                        if unique_ips_count > 3: score += 20
                        elif unique_ips_count > 1: score += 10
                            
                        # 5. Drop Catching (Tire parti de la réputation de vieux domaines) (Max 20 points)
                        if drop_catching_days is not None and drop_catching_days < 14 and aging_days > 365:
                            score += 20
                            
                        # Sécurité max
                        sophistication_score = min(score, 100)

                        data_points.append({
                            "aging_days": aging_days,
                            "takedown_hours": takedown_dur,
                            "takedown_reason": takedown_reason,
                            "tld": tld,
                            "trg": trg,
                            "has_reup": has_reup,
                            "drop_catching_days": drop_catching_days,
                            "domain_length": domain_length,
                            "unique_ips_count": unique_ips_count,
                            "sophistication_score": sophistication_score
                        })

    print(f"[+] Total domaines traités: {len(data_points)}")

    if not data_points:
        print("[!] Pas de points valides générés.")
        return

    # Hypothèse 2 : Corrélation Âge (X) vs Survie (Y)
    # L'objectif est de vérifier si vieillir un domaine augmente significativement sa durée de survie avant takedown.
    plt.figure(figsize=(10, 6))
    x_aging = [d["aging_days"] for d in data_points]
    y_surv = [d["takedown_hours"] for d in data_points]
    
    sns.scatterplot(x=x_aging, y=y_surv, alpha=0.6, color="purple", s=100)
    plt.title("H2: Corrélation entre Âge et Durée de Survie")
    plt.xlabel("Vieillissement (Jours entre création et attaque)")
    plt.ylabel("Survie (Heures avant Takedown)")
    
    # Ajout ligne de tendance
    if len(x_aging) > 1:
        z = np.polyfit(x_aging, y_surv, 1)
        p = np.poly1d(z)
        plt.plot(sorted(x_aging), p(sorted(x_aging)), "r--", alpha=0.8, label="Tendance")
        plt.legend()
        
    plt.tight_layout()
    plt.savefig(GRAPHS_DIR / "h2_age_vs_survie.png", dpi=300)
    plt.close()

    # Hypothèse 3 : Impact Type de Takedown
    plt.figure(figsize=(10, 6))
    valid_h3 = [d for d in data_points if d["takedown_reason"]]
    
    if valid_h3:
        sns.boxplot(
            x=[d["takedown_reason"] for d in valid_h3], 
            y=[d["aging_days"] for d in valid_h3],
            palette="Set2"
        )
        # Échelle Log si les valeurs sont très dispersées
        plt.yscale('log')
        plt.title("H3: Âge du domaine au moment du Takedown (Échelle Log)")
        plt.xlabel("Type de Takedown (DNS, WHOIS, Content)")
        plt.ylabel("Âge (Jours)")
        plt.tight_layout()
        plt.savefig(GRAPHS_DIR / "h3_type_takedown_age.png", dpi=300)
    plt.close()

    # Hypothèse 4 : Résilience (Re-Up)
    plt.figure(figsize=(8, 6))
    reups = [1 if d["has_reup"] else 0 for d in data_points]
    reup_pct = (sum(reups) / len(reups)) * 100 if reups else 0
    
    plt.bar(["Tentative Re-up (NXDOMAIN -> NOERROR)", "Morts définitevement"],
            [sum(reups), len(reups)-sum(reups)], 
            color=["orangered", "darkcyan"])
    plt.title(f"H4: Résilience des attaques (Fast-Flux / Re-Up)\n({reup_pct:.1f}% des domaines de l'échantillon)")
    plt.ylabel("Nombre de domaines")
    plt.tight_layout()
    plt.savefig(GRAPHS_DIR / "h4_resilience_reup.png", dpi=300)
    plt.close()

    # Hypothèse 5 : Spécialisation TLD (Premium vs Low-Cost)
    # Ex: on catégorise .com, .org, .net comme premium, le reste comme low-cost (simplification)
    premium_tlds = ["com", "org", "net", "edu", "gov", "fr"]
    premium_ages = [d["aging_days"] for d in data_points if d["tld"] in premium_tlds]
    lowcost_ages = [d["aging_days"] for d in data_points if d["tld"] not in premium_tlds]

    plt.figure(figsize=(10, 6))
    sns.kdeplot(premium_ages, fill=True, label=f"TLD Premium (n={len(premium_ages)})", color="blue", alpha=0.5)
    sns.kdeplot(lowcost_ages, fill=True, label=f"TLD Low-Cost (n={len(lowcost_ages)})", color="red", alpha=0.5)
    
    plt.xlim(0, max((premium_ages + lowcost_ages) or [30])) # Limite visuelle max
    plt.title("H5: Spécialisation des TLD (Hit-and-run vs Vieillissement)")
    plt.xlabel("Vieillissement (Jours)")
    plt.ylabel("Densité")
    plt.legend()
    plt.tight_layout()
    plt.savefig(GRAPHS_DIR / "h5_specialisation_tld.png", dpi=300)
    plt.close()

    # Hypothèse 6 : Drop Catching (Recyclage de vieux domaines)
    # Comparaison de l'âge total du domaine vs le temps écoulé depuis sa dernière "mise à jour" (qui trahit un rachat)
    plt.figure(figsize=(10, 6))
    drop_data = [d for d in data_points if d.get("drop_catching_days") is not None]
    
    if drop_data:
        x_total_age = [d["aging_days"] for d in drop_data]
        y_recent_update = [d["drop_catching_days"] for d in drop_data]
        
        sns.scatterplot(x=x_total_age, y=y_recent_update, alpha=0.7, color="teal", s=80)
        plt.plot([0, max(x_total_age or [1])], [0, max(x_total_age or [1])], 'r--', alpha=0.5, label="Mise à jour = Création")
        
        plt.title("H6: Détection de Drop Catching (Âge total vs Jours depuis la dernière MAJ)")
        plt.xlabel("Âge total du domaine (Jours)")
        plt.ylabel("Jours écoulés entre la dernière MAJ (ud) et l'attaque")
        plt.legend()
        plt.tight_layout()
        plt.savefig(GRAPHS_DIR / "h6_drop_catching.png", dpi=300)
    plt.close()

    # Hypothèse 7 : Taux d'Uptime malveillant selon le Secteur Cible
    # Regrouper les cibles pour voir qui réagit le plus vite
    plt.figure(figsize=(12, 6))
    valid_h7 = [d for d in data_points if d.get("trg") and d["takedown_hours"] is not None]
    
    if valid_h7:
        # On ne garde que les top 5 cibles pour la lisibilité
        from collections import Counter
        top_targets = [t[0] for t in Counter([d["trg"] for d in valid_h7 if d["trg"] != "unknown"]).most_common(5)]
        h7_data = [d for d in valid_h7 if d["trg"] in top_targets]
        
        if h7_data:
            sns.boxplot(x=[d["trg"] for d in h7_data], y=[d["takedown_hours"] for d in h7_data], palette="magma")
            plt.title("H7: Réactivité Défensive par Cible (USPS, Banques, etc.)")
            plt.xlabel("Cible usurprée (Target)")
            plt.ylabel("Survie avant Takedown (Heures)")
            plt.tight_layout()
            plt.savefig(GRAPHS_DIR / "h7_reactivite_cible.png", dpi=300)
    plt.close()

    # Hypothèse 8 : Morphologie du Nom de Domaine
    # Regardons si la taille du nom a un impact sur sa longévité (les très longs sont-ils détectés plus vite ?)
    plt.figure(figsize=(10, 6))
    x_len = [d["domain_length"] for d in data_points]
    y_surv_h8 = [d["takedown_hours"] for d in data_points]
    
    sns.scatterplot(x=x_len, y=y_surv_h8, alpha=0.5, color="orange", s=60)
    # Tendance morphologie
    if len(x_len) > 1:
        z_len = np.polyfit(x_len, y_surv_h8, 1)
        p_len = np.poly1d(z_len)
        plt.plot(sorted(x_len), p_len(sorted(x_len)), "r--", alpha=0.8)
        
    plt.title("H8: Morphologie - Longueur du domaine vs Temps de Survie")
    plt.xlabel("Longueur du domaine (sans TLD)")
    plt.ylabel("Survie avant Takedown (Heures)")
    plt.tight_layout()
    plt.savefig(GRAPHS_DIR / "h8_morphologie_longueur.png", dpi=300)
    plt.close()

    # Hypothèse 9 : Infrastructure et IP Partagées (Fast Flux / Résilience IP)
    plt.figure(figsize=(10, 6))
    # Boite à moustaches: Âge selon le nombre d'IPs uniques (plus d'IP = domaine géré de façon plus pro ?)
    sns.boxplot(x=[d["unique_ips_count"] for d in data_points], 
                y=[d["aging_days"] for d in data_points],
                palette="viridis")
    plt.yscale('log')
    plt.title("H9: Infrastructure IP - Nombre d'IPs uniques de résolution vs Âge du Domaine")
    plt.xlabel("Nombre d'Adresses IP distinctes (A-Records observés)")
    plt.ylabel("Vieillissement du Domaine (Jours - Échelle Log)")
    plt.tight_layout()
    plt.savefig(GRAPHS_DIR / "h9_infrastructure_ips.png", dpi=300)
    plt.close()

    # Hypothèse 10 : Score de Sophistication de l'Infrastructure Criminelle
    plt.figure(figsize=(10, 6))
    scores = [d["sophistication_score"] for d in data_points]
    
    # Histogramme de distribution des scores
    sns.histplot(scores, bins=20, kde=True, color="crimson")
    plt.title("H10: Distribution du Score de Sophistication des Attaques (0 - 100)")
    plt.xlabel("Score de Sophistication (Pondération Âge, TLD, Fast-Flux, Drop Catching...)")
    plt.ylabel("Nombre de Domaines")
    
    # Lignes pour séparer grossièrement les "niveaux"
    plt.axvline(x=25, color='gray', linestyle='--', label='Faible Sophistication')
    plt.axvline(x=60, color='black', linestyle='--', label='Haute Sophistication')
    plt.legend()
    
    plt.tight_layout()
    plt.savefig(GRAPHS_DIR / "h10_sophistication_score.png", dpi=300)
    plt.close()

    print("[*] Graphiques générés dans :", GRAPHS_DIR)

if __name__ == "__main__":
    main()
