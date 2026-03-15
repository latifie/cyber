import json
from pathlib import Path
from datetime import datetime, timezone
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import pandas as pd
import warnings
warnings.filterwarnings('ignore')

def get_tld(rd):
    if not rd or '.' not in rd: return "unknown"
    return rd.split('.')[-1].lower()

def parse_date(date_str):
    if not date_str: return None
    try:
        if 'T' in date_str:
            dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)
            return dt
        return datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except:
        return None

def main():
    sns.set_theme(style="whitegrid")
    
    base_dir = Path("/root/cyber")
    out_dir = base_dir / "adam_final"
    out_dir.mkdir(parents=True, exist_ok=True)
    
    # ---------------------------------------------------------
    # CHARGEMENT DES NOMS DE REGISTRARS (CSV)
    # ---------------------------------------------------------
    registrar_map = {}
    csv_path = base_dir / "registrar-ids-1.csv"
    if csv_path.exists():
        try:
            reg_df = pd.read_csv(csv_path)
            reg_df.columns = reg_df.columns.str.strip().str.replace('"', '')
            if "ID" in reg_df.columns and "Registrar Name" in reg_df.columns:
                registrar_map = reg_df.set_index("ID")["Registrar Name"].astype(str).to_dict()
                registrar_map = {str(k).strip(): v for k, v in registrar_map.items()}
                print(f"[*] Fichier CSV des Registrars chargé : {len(registrar_map)} noms trouvés.")
        except Exception as e:
            print(f"[!] Erreur lors de la lecture du CSV registrar : {e}")
    else:
        print("[!] Attention : fichier registrar-ids-1.csv introuvable dans /root/cyber/")

    # ---------------------------------------------------------
    # RECHERCHE ET LECTURE DU FICHIER JSONL
    # ---------------------------------------------------------
    data_files = list((base_dir / "analysis_results").glob("malicious_domains_takedown_whois_full_*.jsonl"))
    if not data_files:
        print("No files found")
        return
        
    latest_file = sorted(data_files)[-1]
    
    filter_stats = {
        "neg_aging": 0,
        "neg_update": 0,
        "neg_uptime_dur": 0,
        "no_pre_uptime": 0
    }

    total_processed = 0
    records = []
    sample_timeline = []
    
    print(f"[*] Début de l'analyse en streaming de : {latest_file.name}")
    
    with open(latest_file, 'r', encoding='utf-8') as f:
        for line in f:
            total_processed += 1
            if total_processed % 100000 == 0:
                print(f"[~] ... {total_processed:,} domaines analysés ...")
            if not line.strip(): continue
            try:
                rec = json.loads(line)
            except:
                continue
                
            discovery = parse_date(rec.get("discovery_time"))
            if not discovery: continue
            
            whois = rec.get("whois_bd") or {}
            cd = parse_date(whois.get("cd"))
            ud = parse_date(whois.get("ud"))
            ed = parse_date(whois.get("ed"))
            iana_id = whois.get("iana_id")
            if iana_id: iana_id = str(iana_id)
            
            if not cd or not ud:
                for u in rec.get("uptime", []):
                    if u.get("type") == "whois":
                        if not cd and u.get("cd"): cd = parse_date(u.get("cd"))
                        if not ud and u.get("ud"): ud = parse_date(u.get("ud"))
                        if not ed and u.get("ed"): ed = parse_date(u.get("ed"))
            
            if not cd: continue
            
            aging_time = (discovery - cd).total_seconds() / 86400
            
            if aging_time < 0:
                filter_stats["neg_aging"] += 1
                continue
            if aging_time > 15000:
                continue
                
            update_delay = None
            if ud:
                update_delay = (discovery - ud).total_seconds() / 86400
                if update_delay < 0:
                    filter_stats["neg_update"] += 1
                    update_delay = None
            
            expiration_gap = (ed - discovery).total_seconds() / 86400 if ed else None
            
            meta = rec.get("metadata", {})
            trg = meta.get("trg", "unknown")
            
            takedown = rec.get("takedown", {})
            uptime_dur = takedown.get("uptime_dur")
            if uptime_dur is not None and uptime_dur < 0:
                filter_stats["neg_uptime_dur"] += 1
                uptime_dur = None
            
            cluster = "Sleeper (>30j)"
            if aging_time <= 1: cluster = "Immédiat (<1j)"
            elif aging_time <= 7: cluster = "Rapide (1-7j)"
            elif aging_time <= 30: cluster = "Moyen (7-30j)"
            
            # --- NOUVEAUX CLUSTERS ETENDUS ---
            ext_cluster = "Legacy (>1an)"
            if aging_time <= 1: ext_cluster = "Immédiat (<1j)"
            elif aging_time <= 7: ext_cluster = "Rapide (1-7j)"
            elif aging_time <= 30: ext_cluster = "Moyen (7-30j)"
            elif aging_time <= 90: ext_cluster = "Sleeper Court (1-3m)"
            elif aging_time <= 180: ext_cluster = "Deep Sleeper (3-6m)"
            elif aging_time <= 365: ext_cluster = "Zombie (6-12m)"

            rd = rec.get("rd", "unknown")
            tld = get_tld(rd)
            
            # --- EXTRACTION CHINE (TLD + MAXMIND CC_CODE) ---
            is_cn = False
            if tld == "cn":
                is_cn = True
            else:
                host_info = rec.get("host_info", {})
                maxmind = host_info.get("maxmind", [])
                for obj in maxmind:
                    answers = obj.get("answers", {})
                    cc = answers.get("cc_code")
                    if cc and str(cc).upper() == "CN":
                        is_cn = True
                        break

            ip_changes = 0
            unique_ips_before = set()
            html_changes_count = 0
            has_pre_attack_changes = False
            last_ip = None
            last_html = None
            
            timeline_events = {
                "cd": cd,
                "discovery": discovery,
                "ip_change": None,
                "html_change": None
            }
            
            pre_uptime_count = 0
            for u in rec.get("uptime", []):
                dt = parse_date(u.get("dt"))
                if not dt: continue
                
                if dt > discovery: continue 
                pre_uptime_count += 1
                
                if u.get("arec"):
                    ip_tuple = tuple(sorted(u["arec"]))
                    for ip in ip_tuple: unique_ips_before.add(ip)
                    if last_ip and last_ip != ip_tuple:
                        ip_changes += 1
                        if (discovery - dt).total_seconds() / 86400 <= 7:
                            timeline_events["ip_change"] = dt
                            has_pre_attack_changes = True
                    last_ip = ip_tuple
                
                if u.get("html_ssdeep"):
                    h = u.get("html_ssdeep")
                    if last_html and h != last_html:
                        html_changes_count += 1
                        if (discovery - dt).total_seconds() / 86400 <= 7:
                            timeline_events["html_change"] = dt
                            has_pre_attack_changes = True
                    last_html = h
            
            if pre_uptime_count == 0:
                filter_stats["no_pre_uptime"] += 1
                    
            dns_changes = len(unique_ips_before)
            year_discovery = discovery.year
            
            records.append({
                "rd": rd,
                "tld": tld,
                "aging_time": aging_time,
                "aging_cluster": cluster,
                "extended_cluster": ext_cluster, 
                "is_cn": is_cn, 
                "update_delay": update_delay,
                "expiration_gap": expiration_gap,
                "uptime_dur": uptime_dur,
                "iana_id": iana_id,
                "trg": trg,
                "ip_changes": ip_changes,
                "html_changes": html_changes_count,
                "dns_changes": dns_changes, 
                "has_pre_attack_changes": has_pre_attack_changes,
                "year": year_discovery,
                "month": discovery.month,
                "year_month": discovery.strftime("%Y-%m"),
                "weekday": discovery.strftime("%A"),
                "rd_len": len(rd),
                "content_versions": html_changes_count + 1 if last_html else 0
            })
            
            if has_pre_attack_changes and len(sample_timeline) < 7:
                sample_timeline.append({
                    "aging_time": aging_time,
                    "events": timeline_events
                })
            
    print(f"[*] Conversion en DataFrame Pandas. RAM safe.")
    df = pd.DataFrame(records)
    
    # ---------------------------------------------------------
    # PRÉPARATION GLOBALE DES COLONNES POUR LES GRAPHIQUES
    # ---------------------------------------------------------
    df["aging_cluster"] = pd.Categorical(df["aging_cluster"], categories=["Immédiat (<1j)", "Rapide (1-7j)", "Moyen (7-30j)", "Sleeper (>30j)"], ordered=True)
    df["strat_group"] = df["aging_cluster"].apply(lambda x: "Sleeper" if "Sleeper" in str(x) else "Sprinter")
    
    # Ajout de l'ordre pour les nouveaux clusters
    extended_cats = ["Immédiat (<1j)", "Rapide (1-7j)", "Moyen (7-30j)", "Sleeper Court (1-3m)", "Deep Sleeper (3-6m)", "Zombie (6-12m)", "Legacy (>1an)"]
    df["extended_cluster"] = pd.Categorical(df["extended_cluster"], categories=extended_cats, ordered=True)

    df["registrar_name"] = df["iana_id"].map(registrar_map).fillna("ID: " + df["iana_id"].astype(str))
    
    print(f"Total domains processed: {total_processed}")
    print(f"Total valid domains in DataFrame: {len(df)}")
    print(f"Diagnostics: {filter_stats}")
    print(f"[*] Génération des graphiques classiques...")


    # 01. Distribution globale de l'âge (Log scale)
    plt.figure()
    sns.histplot(df["aging_time"], bins=50, kde=True, log_scale=True, color="#3498db")
    plt.title("Thème 1: Distribution de l'Âge des Domaines au Moment de l'Attaque")
    plt.xlabel("Temps de Vieillissement (jours, échelle log)")
    plt.ylabel("Nombre de domaines")
    plt.savefig(out_dir / "01_distribution_age_log.png", dpi=300, bbox_inches='tight')
    plt.close()

    # 02. CDF du Temps de Vieillissement (Échelle Log)
    df_valid_age = df[df["aging_time"] > 0]
    plt.figure()
    sns.ecdfplot(data=df_valid_age, x="aging_time", color="#e74c3c")
    plt.title("Thème 1: CDF du Temps de Vieillissement (Échelle Log)")
    plt.xlabel("Temps de Vieillissement (jours, log)")
    plt.ylabel("Proportion Cumulée")
    plt.xscale('log')
    plt.savefig(out_dir / "02_proportion_cumulee_age.png", dpi=300, bbox_inches='tight')
    plt.close()

    # 03. Délai de Mise à Jour WHOIS vs Âge (Carte de Densité Hexbin)
    df_updates = df[(df["update_delay"].notna()) & (df["update_delay"] >= 0)].copy()
    if not df_updates.empty:
        plt.figure(figsize=(10, 6))
        plt.hexbin(df_updates["aging_time"], df_updates["update_delay"], gridsize=40, cmap='Purples', xscale='log', yscale='symlog', mincnt=1, bins='log')
        plt.colorbar(label='log10(Nombre de domaines)')
        plt.title("Thème 2: Délai de Mise à Jour WHOIS vs Âge (Carte de Densité)")
        plt.xlabel("Temps de Vieillissement (jours)")
        plt.ylabel("Délai de Mise à Jour (jours avant l'attaque)")
        plt.axhline(0, color='red', linestyle='--', alpha=0.5)
        plt.tight_layout()
        plt.savefig(out_dir / "03_maj_whois_vs_age.png", dpi=300)
        plt.close()

    # 04. Délai de MAJ pour les 'Sleepers' (>180j)
    old_domains = df_updates[df_updates["aging_time"] > 180]
    if len(old_domains) > 0:
        plt.figure()
        sns.histplot(old_domains["update_delay"], bins=50, kde=True, color="#2ecc71")
        plt.title("Thème 2: Délai de MAJ pour les 'Sleepers' (Âge > 180 jours)")
        plt.xlabel("Délai de Mise à Jour (jours avant l'attaque)")
        plt.ylabel("Nombre de domaines")
        plt.xlim(0, 400)
        plt.savefig(out_dir / "04_dist_maj_sleepers.png", dpi=300, bbox_inches='tight')
        plt.close()

    # 05. Stratégies de Vieillissement selon le Top 15 Registrars (Noms réels)
    top_registrars_named = df[df["iana_id"] != "None"]["registrar_name"].value_counts().nlargest(15).index.tolist()
    df_registrars_named = df[df["registrar_name"].isin(top_registrars_named)]
    plt.figure(figsize=(14, 8))
    sns.boxplot(data=df_registrars_named, x="registrar_name", y="aging_time", order=top_registrars_named, palette="viridis")
    plt.yscale("log")
    plt.title("Thème 3: Stratégies de Vieillissement selon le Top des Registrars")
    plt.xlabel("Registrar")
    plt.ylabel("Temps de Vieillissement (jours, échelle log)")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig(out_dir / "05_age_par_registrar.png", dpi=300, bbox_inches='tight')
    plt.close()

    # 06. Temps de Vieillissement par Marque Ciblée
    top_targets = df[df["trg"] != "unknown"]["trg"].value_counts().nlargest(12).index.tolist()
    df_targets = df[df["trg"].isin(top_targets)]
    if len(df_targets) > 0:
        target_stats = df_targets.groupby("trg")["aging_time"].agg(["median", lambda x: x.quantile(0.90)]).reset_index()
        target_stats.columns = ["Target", "Median", "90th_Percentile"]
        target_stats = target_stats.sort_values(by="Median", ascending=False).set_index("Target")
        target_stats.plot(kind="bar", figsize=(12, 6), color=["#34495e", "#e67e22"])
        plt.yscale("log")
        plt.title("Thème 4: Temps de Vieillissement par Marque Ciblée (Médiane vs 90ème centile)")
        plt.xlabel("Marque Usurpée")
        plt.ylabel("Temps de Vieillissement (jours, échelle log)")
        plt.xticks(rotation=45)
        plt.legend(["Âge Médian", "Âge 90ème Centile"])
        plt.tight_layout()
        plt.savefig(out_dir / "06_age_par_marque.png", dpi=300, bbox_inches='tight')
        plt.close()

    # 07. Évolution Annuelle de l'Âge Médian
    yearly_median = df.groupby("year")["aging_time"].median().reset_index()
    yearly_counts = df.groupby("year").size()
    valid_years = yearly_counts[yearly_counts > 0].index
    yearly_median = yearly_median[yearly_median["year"].isin(valid_years)]
    if len(yearly_median) > 0:
        plt.figure()
        sns.lineplot(data=yearly_median, x="year", y="aging_time", marker="s", color="#c0392b", linewidth=2.5)
        plt.title("Thème 5: Évolution Annuelle de l'Âge Médian des Domaines")
        plt.xlabel("Année de l'Attaque (Découverte)")
        plt.ylabel("Temps de Vieillissement Médian (jours)")
        min_year = int(yearly_median["year"].min())
        max_year = int(yearly_median["year"].max())
        plt.xticks(range(min_year, max_year + 1))
        plt.savefig(out_dir / "07_evolution_annuelle_age.png", dpi=300, bbox_inches='tight')
        plt.close()

    # 08. Frise Pré-Militarisation
    if len(sample_timeline) > 0:
        plt.figure(figsize=(10, 6))
        for i, row in enumerate(sample_timeline):
            y = i
            ev = row["events"]
            plt.plot([ev["cd"], ev["discovery"]], [y, y], color="grey", alpha=0.3, zorder=1)
            plt.scatter(ev["cd"], y, color="#2c3e50", marker="s", s=80, label="Création" if i==0 else "", zorder=2)
            plt.scatter(ev["discovery"], y, color="#c0392b", marker="X", s=120, label="Découverte" if i==0 else "", zorder=2)
            if ev.get("ip_change"):
                plt.scatter(ev["ip_change"], y, color="#27ae60", marker="^", s=100, label="Changement IP (<7j)" if i==0 else "", zorder=3)
            if ev.get("html_change"):
                plt.scatter(ev["html_change"], y, color="#f39c12", marker="v", s=100, label="Changement HTML (<7j)" if i==0 else "", zorder=3)
                
        plt.yticks(range(len(sample_timeline)), [f"Dom {i+1} (Âge:{int(row['aging_time'])}j)" for i, row in enumerate(sample_timeline)])
        plt.title("Thème 6: Frise Pré-Militarisation (Domaines avec mutations récentes)")
        plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
        plt.tight_layout()
        plt.savefig(out_dir / "08_frise_chronologique_mutations.png", dpi=300, bbox_inches='tight')
        plt.close()

    # 09. Classification des Stratégies
    plt.figure(figsize=(8, 6))
    ax = sns.countplot(data=df, x="aging_cluster", palette="magma")
    plt.title("Ch 2: Classification des Stratégies de Vieillissement")
    plt.xlabel("Cluster Stratégique")
    plt.ylabel("Nombre de Domaines")
    for p in ax.patches:
        ax.annotate(f"{int(p.get_height())}", (p.get_x() + p.get_width() / 2., p.get_height()), ha='center', va='bottom')
    plt.savefig(out_dir / "09_classification_clusters_strategies.png", dpi=300, bbox_inches='tight')
    plt.close()

    # 10. Espérance de Vie Opérationnelle (Survie) vs Âge (Carte de Densité Hexbin)
    df_surv = df.dropna(subset=["uptime_dur"]).copy()
    if not df_surv.empty:
        plt.figure(figsize=(10, 6))
        plt.hexbin(df_surv["aging_time"], df_surv["uptime_dur"], gridsize=40, cmap='Blues', xscale='symlog', yscale='symlog', mincnt=1, bins='log')
        plt.colorbar(label='log10(Nombre de domaines)')
        plt.title("Ch 7: Espérance de Vie Opérationnelle (Survie) vs Âge (Carte de Densité)")
        plt.xlabel("Temps de Vieillissement (jours)")
        plt.ylabel("Durée de Survie (Uptime) Post-Attaque (heures)")
        plt.tight_layout()
        plt.savefig(out_dir / "10_courbe_survie_vs_age.png", dpi=300)
        plt.close()

    # 11. Distribution de l'Écart avant Expiration
    df_exp = df.dropna(subset=["expiration_gap"])
    if len(df_exp) > 0:
        plt.figure()
        sns.histplot(df_exp["expiration_gap"], bins=100, kde=True, color="#d35400")
        plt.title("Ch 9: Distribution de l'Écart avant Expiration")
        plt.xlabel("Jours Séparant la Découverte et l'Expiration")
        plt.ylabel("Nombre de domaines")
        plt.xlim(-50, 750)
        plt.axvline(0, color='r', linestyle='--')
        plt.savefig(out_dir / "11_expiration_gap_strategique.png", dpi=300, bbox_inches='tight')
        plt.close()
        
    # 12. Tempo Opérationnel - Jour de l'Attaque (Weekend Gap)
    plt.figure(figsize=(10, 6))
    days_order = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    ax = sns.countplot(data=df, x="weekday", hue="strat_group", order=days_order, palette="coolwarm")
    plt.title("Hyp. A: Tempo Opérationnel - Jour de l'Attaque (Weekend Gap)")
    plt.xlabel("Jour de la semaine (Découverte)")
    plt.ylabel("Nombre d'attaques")
    plt.xticks(rotation=45)
    plt.legend(title="Stratégie")
    plt.tight_layout()
    plt.savefig(out_dir / "12_analyse_weekend_gap_sprinters_vs_sleepers.png", dpi=300)
    plt.close()

    # 13. Crédibilité Lexicale - Longueur du Nom vs Âge
    plt.figure(figsize=(10, 6))
    sns.scatterplot(data=df, x="rd_len", y="aging_time", hue="aging_cluster", alpha=0.6, palette="viridis")
    plt.yscale("log")
    plt.axvline(10, color="red", linestyle="--", alpha=0.5, label="Seuil Crédibilité (10 chars)")
    plt.title("Hyp. B: Crédibilité Lexicale - Longueur du Nom vs Âge")
    plt.xlabel("Longueur du Root Domain (caractères)")
    plt.ylabel("Temps d'incubation (jours, échelle log)")
    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.tight_layout()
    plt.savefig(out_dir / "13_correlation_longueur_domaine_vs_age.png", dpi=300)
    plt.close()

    # 14. Stratégie Extensions - Proportion Sprinters vs Sleepers (Trié)
    top_tlds = df["tld"].value_counts().nlargest(10).index.tolist()
    if len(top_tlds) > 0:
        plt.figure(figsize=(12, 7))
        tld_dist_fixed = df[df["tld"].isin(top_tlds)].groupby(["tld", "strat_group"]).size().unstack().fillna(0)
        tld_dist_pct_fixed = tld_dist_fixed.div(tld_dist_fixed.sum(axis=1), axis=0) * 100
        if "Sprinter" in tld_dist_pct_fixed.columns:
            tld_dist_pct_fixed = tld_dist_pct_fixed.sort_values(by="Sprinter", ascending=False)
        tld_dist_pct_fixed.plot(kind="bar", stacked=True, color=["#e74c3c", "#3498db"], figsize=(12, 7))
        plt.title("Hyp. C: Stratégie Extensions - Proportion Sprinters vs Sleepers par TLD")
        plt.ylabel("Pourcentage (%)")
        plt.xlabel("TLD (Top 10)")
        plt.axhline(50, color="gray", linestyle="--", alpha=0.5)
        plt.legend(title="Stratégie")
        plt.tight_layout()
        plt.savefig(out_dir / "14_repartition_tld_sprinters_sleepers.png", dpi=300)
        plt.close()

    # 15. Saisonnalité - Volume Mensuel des Attaques
    plt.figure(figsize=(10, 6))
    monthly_data = df.groupby(["month", "strat_group"]).size().reset_index(name="count")
    sns.lineplot(data=monthly_data, x="month", y="count", hue="strat_group", marker="o", linewidth=2.5)
    plt.title("Hyp. D: Saisonnalité - Volume Mensuel des Attaques")
    plt.xlabel("Mois de l'année")
    plt.ylabel("Nombre d'attaques")
    plt.xticks(range(1, 13))
    plt.tight_layout()
    plt.savefig(out_dir / "15_saisonnalite_mensuelle_attaques.png", dpi=300)
    plt.close()

    # 16. ROI de l'Incubation - Survie Médiane post-attaque
    if not df_surv.empty:
        plt.figure(figsize=(10, 6))
        median_surv = df_surv.groupby("aging_cluster")["uptime_dur"].median().reset_index()
        sns.barplot(data=median_surv, x="aging_cluster", y="uptime_dur", palette="magma")
        plt.title("Hyp. E: ROI de l'Incubation - Survie Médiane post-attaque")
        plt.ylabel("Durée de Survie Médiane (Heures)")
        plt.xlabel("Cluster Stratégique d'Âge")
        plt.tight_layout()
        plt.savefig(out_dir / "16_roi_survie_mediane_par_cluster_age.png", dpi=300)
        plt.close()
    
    # 17. Ratio Stratégique des Registrars (Spécialisation)
    top_10_regs = df[df["iana_id"] != "None"]["registrar_name"].value_counts().nlargest(10).index.tolist()
    if len(top_10_regs) > 0:
        plt.figure(figsize=(12, 7))
        reg_dist = df[df["registrar_name"].isin(top_10_regs)].groupby(["registrar_name", "strat_group"]).size().unstack().fillna(0)
        reg_dist_pct = reg_dist.div(reg_dist.sum(axis=1), axis=0) * 100
        if "Sprinter" in reg_dist_pct.columns:
            reg_dist_pct = reg_dist_pct.sort_values(by="Sprinter", ascending=False)
        reg_dist_pct.plot(kind="bar", stacked=True, color=["#e74c3c", "#3498db"], figsize=(12, 7))
        plt.title("Idée A: Ratio Stratégique des Registrars (Spécialisation)")
        plt.ylabel("Pourcentage (%)")
        plt.xlabel("Registrar (Top 10)")
        plt.axhline(50, color="gray", linestyle="--", alpha=0.5)
        plt.legend(title="Stratégie")
        plt.xticks(rotation=45, ha="right")
        plt.tight_layout()
        plt.savefig(out_dir / "17_ratio_strategique_registrars.png", dpi=300)
        plt.close()

    # 18. Complexité d'Infrastructure (Boxplot IPs)
    plt.figure(figsize=(10, 6))
    sns.boxplot(data=df, x="aging_cluster", y="dns_changes", palette="magma")
    plt.yscale("symlog")
    plt.title("Idée B: Complexité Infrastructure - Nombre d'IPs uniques associées")
    plt.xlabel("Cluster Stratégique d'Âge")
    plt.ylabel("Nombre de changements DNS (IPs uniques)")
    plt.tight_layout()
    plt.savefig(out_dir / "18_complexite_infrastructure_ips.png", dpi=300)
    plt.close()

    # 19. La preuve du Drop Catching (Pie Chart)
    old_sleepers = df[df["aging_time"] > 365].copy()
    if not old_sleepers.empty:
        def categorize_drop(ud_val):
            if pd.isna(ud_val) or ud_val < 0: return "Inconnu / Sans MAJ"
            if ud_val <= 3: return "Drop Catching (Rachat, MAJ < 3j)" 
            return "Incubation Classique"
            
        old_sleepers["drop_catch_status"] = old_sleepers["update_delay"].apply(categorize_drop)
        counts = old_sleepers["drop_catch_status"].value_counts()
        
        plt.figure(figsize=(8, 8))
        plt.pie(counts, labels=counts.index, autopct='%1.1f%%', startangle=140, colors=["#95a5a6", "#e74c3c", "#3498db"])
        plt.title("Idée C: Preuve du 'Drop Catching' (Domaines > 1 an)\nOnt-ils été mis à jour administrativement juste avant l'attaque ?")
        plt.savefig(out_dir / "19_preuve_drop_catching_pie.png", dpi=300)
        plt.close()

    # 20. Évolution Temporelle Mensuelle Globale 
    plt.figure(figsize=(14, 6))
    monthly_evolution = df.groupby("year_month")["aging_time"].median().reset_index()
    monthly_evolution = monthly_evolution.sort_values("year_month")
    
    sns.lineplot(data=monthly_evolution, x="year_month", y="aging_time", marker="o", color="#8e44ad", linewidth=2)
    plt.title("Idée D: Évolution Temporelle Détaillée (Mensuelle Globale) de l'Âge Médian")
    plt.xlabel("Mois de Découverte (Année-Mois)")
    plt.ylabel("Temps de Vieillissement Médian (jours)")
    plt.xticks(rotation=90, fontsize=8) 
    plt.tight_layout()
    plt.savefig(out_dir / "20_evolution_mensuelle_globale_age.png", dpi=300)
    plt.close()

    # 21. Évolution Mensuelle Fractionnée par Année
    unique_years = sorted(df["year"].unique())
    for y in unique_years:
        df_year = df[df["year"] == y]
        if len(df_year) > 100: 
            plt.figure(figsize=(10, 6))
            monthly_year_evol = df_year.groupby("month")["aging_time"].median().reset_index()
            sns.lineplot(data=monthly_year_evol, x="month", y="aging_time", marker="o", color="#c0392b", linewidth=2)
            plt.title(f"Évolution Mensuelle de l'Âge Médian pour l'année {y}")
            plt.xlabel("Mois")
            plt.ylabel("Temps de Vieillissement Médian (jours)")
            plt.xticks(range(1, 13))
            plt.tight_layout()
            plt.savefig(out_dir / f"21_evolution_mensuelle_{y}_age.png", dpi=300)
            plt.close()


    print(f"[*] Génération des nouveaux graphiques (NEW_)...")

    # NEW_22 : Évolution des Stratégies de Vieillissement par Année (Échelle Étendue)
    plt.figure(figsize=(14, 7))
    sns.countplot(data=df, x="year", hue="extended_cluster", palette="magma")
    plt.title("NEW 22: Évolution des Stratégies de Vieillissement par Année (Échelle Étendue)")
    plt.xlabel("Année")
    plt.ylabel("Nombre de domaines")
    plt.legend(title="Catégories d'Âge", bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.tight_layout()
    plt.savefig(out_dir / "NEW_22_strategies_par_annee.png", dpi=300)
    plt.close()

    # NEW_23 : Zoom CHINE - Délai de Mise à Jour WHOIS vs Âge (Contourner le RGPD)
    df_cn = df[(df["is_cn"] == True) & (df["update_delay"].notna()) & (df["update_delay"] >= 0)]
    if not df_cn.empty:
        plt.figure(figsize=(10, 6))
        plt.hexbin(df_cn["aging_time"], df_cn["update_delay"], gridsize=40, cmap='Reds', xscale='log', yscale='symlog', mincnt=1, bins='log')
        plt.colorbar(label='log10(Nombre de domaines Chinois)')
        plt.title("NEW 23: Zoom CHINE - Délai de Mise à Jour WHOIS vs Âge")
        plt.xlabel("Temps de Vieillissement (jours)")
        plt.ylabel("Délai de Mise à Jour (jours avant l'attaque)")
        plt.axhline(0, color='blue', linestyle='--', alpha=0.5)
        plt.tight_layout()
        plt.savefig(out_dir / "NEW_23_zoom_chine_maj_vs_age.png", dpi=300)
        plt.close()

        # NEW_24 : Zoom CHINE - Délai de MAJ pour les Sleepers Chinois (> 180 jours)
        old_cn = df_cn[df_cn["aging_time"] > 180]
        if not old_cn.empty:
            plt.figure(figsize=(10, 6))
            sns.histplot(old_cn["update_delay"], bins=50, kde=True, color="#c0392b")
            plt.title("NEW 24: Zoom CHINE - Délai de MAJ pour les Sleepers (> 180 jours)")
            plt.xlabel("Délai de Mise à Jour (jours avant l'attaque)")
            plt.ylabel("Nombre de domaines")
            plt.xlim(0, 400)
            plt.tight_layout()
            plt.savefig(out_dir / "NEW_24_chine_maj_sleepers.png", dpi=300)
            plt.close()

    # NEW_25 : Preuve du "Burn After Use" (Écart avant expiration par Stratégie)
    df_exp = df.dropna(subset=["expiration_gap"])
    # On filtre pour faire un beau zoom sur la dernière année de vie
    df_exp_zoom = df_exp[(df_exp["expiration_gap"] >= -50) & (df_exp["expiration_gap"] <= 400)]
    if not df_exp_zoom.empty:
        plt.figure(figsize=(10, 6))
        sns.kdeplot(data=df_exp_zoom, x="expiration_gap", hue="strat_group", common_norm=False, fill=True, palette="Set1")
        plt.title("NEW 25: Preuve du 'Burn After Use' (Sprinters vs Sleepers)")
        plt.xlabel("Jours Restants avant Expiration (lors de l'attaque)")
        plt.ylabel("Densité de distribution")
        plt.axvline(0, color='red', linestyle='--', alpha=0.8, label='Péremption (0j)')
        plt.axvline(365, color='blue', linestyle='--', alpha=0.8, label='1 An de validité (365j)')
        plt.tight_layout()
        plt.savefig(out_dir / "NEW_25_burn_after_use.png", dpi=300)
        plt.close()

    # NEW_25 : Preuve 
    df_exp = df.dropna(subset=["expiration_gap"])
    df_exp_zoom = df_exp[(df_exp["expiration_gap"] >= -50) & (df_exp["expiration_gap"] <= 400)]
    if not df_exp_zoom.empty:
        fig, axes = plt.subplots(2, 1, figsize=(10, 8), sharex=True)
        
        # Étages du haut : Les Sprinters
        sns.histplot(data=df_exp_zoom[df_exp_zoom["strat_group"] == "Sprinter"], 
                     x="expiration_gap", color="#e74c3c", bins=50, kde=True, ax=axes[0])
        axes[0].set_title("NEW 25: Stratégie des Sprinters (Attaque quasi-immédiate)")
        axes[0].set_ylabel("Nombre de domaines")
        axes[0].axvline(365, color='blue', linestyle='--', alpha=0.8, label='1 An de validité (365j)')
        axes[0].legend()
        
        # Étage du bas : Les Sleepers
        sns.histplot(data=df_exp_zoom[df_exp_zoom["strat_group"] == "Sleeper"], 
                     x="expiration_gap", color="#3498db", bins=50, kde=True, ax=axes[1])
        axes[1].set_title("Stratégie des Sleepers (Burn After Use)")
        axes[1].set_xlabel("Jours Restants avant Expiration (lors de l'attaque)")
        axes[1].set_ylabel("Nombre de domaines")
        axes[1].axvline(0, color='red', linestyle='--', alpha=0.8, label='Péremption (0j)')
        axes[1].legend()
        
        plt.tight_layout()
        plt.savefig(out_dir / "NEW_26_burn_after_use.png", dpi=300)
        plt.close()

    print(f"[*] Tous les graphiques ont été générés avec succès dans {out_dir}")

if __name__ == "__main__":
    main()