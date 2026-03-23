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
    out_dir = base_dir / "result_graphs/graphiques_en"
    out_dir.mkdir(parents=True, exist_ok=True)
    
    # CHARGEMENT DES NOMS DE REGISTRARS (CSV)

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

    # RECHERCHE ET LECTURE DU FICHIER JSONL

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
            
            cluster = "Domaine en Incubation (>30j)"
            if aging_time <= 1: cluster = "Militarisation Directe (<1j)"
            elif aging_time <= 7: cluster = "Militarisation Rapide (1-7j)"
            elif aging_time <= 30: cluster = "Incubation Précoce (7-30j)"
            

            ext_cluster = "Infrastructure Mature (>1an)"
            if aging_time <= 1: ext_cluster = "Militarisation Directe (<1j)"
            elif aging_time <= 7: ext_cluster = "Militarisation Rapide (1-7j)"
            elif aging_time <= 30: ext_cluster = "Incubation Précoce (7-30j)"
            elif aging_time <= 90: ext_cluster = "Incubation Courte (1-3 mois)"
            elif aging_time <= 180: ext_cluster = "Incubation Prolongée (3-6 mois)"
            elif aging_time <= 365: ext_cluster = "Incubation Longue (6-12 mois)"

            rd = rec.get("rd", "unknown")
            tld = get_tld(rd)
            
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
            
            last_mutation_dt = None
            
            pre_uptime_count = 0
            for u in rec.get("uptime", []):
                dt = parse_date(u.get("dt"))
                if not dt: continue
                
                if dt > discovery: continue 
                pre_uptime_count += 1
                is_mutation = False
                
                if u.get("arec"):
                    ip_tuple = tuple(sorted(u["arec"]))
                    for ip in ip_tuple: unique_ips_before.add(ip)
                    if last_ip and last_ip != ip_tuple:
                        ip_changes += 1
                        if (discovery - dt).total_seconds() / 86400 <= 7:
                            timeline_events["ip_change"] = dt
                            has_pre_attack_changes = True
                        is_mutation = True
                    last_ip = ip_tuple
                
                if u.get("html_ssdeep"):
                    h = u.get("html_ssdeep")
                    if last_html and h != last_html:
                        html_changes_count += 1
                        if (discovery - dt).total_seconds() / 86400 <= 7:
                            timeline_events["html_change"] = dt
                            has_pre_attack_changes = True
                        is_mutation = True
                    last_html = h
                
                # Mise à jour du timestamp de la dernière mutation
                if is_mutation:
                    if last_mutation_dt is None or dt > last_mutation_dt:
                        last_mutation_dt = dt
            
            if pre_uptime_count == 0:
                filter_stats["no_pre_uptime"] += 1
                    
            dns_changes = len(unique_ips_before)
            year_discovery = discovery.year
            
            # --- Calcul de l'écart entre la dernière mutation (Militarisation) et la découverte ---
            weaponization_gap = (discovery - last_mutation_dt).total_seconds() / 86400 if last_mutation_dt else None
            
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
                "content_versions": html_changes_count + 1 if last_html else 0,
                "weaponization_gap": weaponization_gap
            })
            
            if has_pre_attack_changes and len(sample_timeline) < 7:
                sample_timeline.append({
                    "aging_time": aging_time,
                    "events": timeline_events
                })
            
    print(f"[*] Conversion en DataFrame Pandas. RAM safe.")
    df = pd.DataFrame(records)
    
    df["aging_cluster"] = pd.Categorical(df["aging_cluster"], categories=["Militarisation Directe (<1j)", "Militarisation Rapide (1-7j)", "Incubation Précoce (7-30j)", "Domaine en Incubation (>30j)"], ordered=True)
    df["strat_group"] = df["aging_cluster"].apply(lambda x: "Incubation" if "Domaine en Incubation (>30j)" in str(x) else "Militarisation Directe")
    
    # Ajout de l'ordre pour les nouveaux clusters
    extended_cats = ["Militarisation Directe (<1j)", "Militarisation Rapide (1-7j)", "Incubation Précoce (7-30j)", "Incubation Courte (1-3 mois)", "Incubation Prolongée (3-6 mois)", "Incubation Longue (6-12 mois)", "Infrastructure Mature (>1an)"]
    df["extended_cluster"] = pd.Categorical(df["extended_cluster"], categories=extended_cats, ordered=True)

    df["registrar_name"] = df["iana_id"].map(registrar_map).fillna("ID: " + df["iana_id"].astype(str))
    
    df["quarter"] = df["year"].astype(str) + "-Q" + ((df["month"] - 1) // 3 + 1).astype(str)
    
    print(f"Nombre total de domaines analysés : {total_processed:,}")
    print(f"Domaines valides dans le DataFrame : {len(df):,}")
    print(f"Statistiques de filtrage : {filter_stats}")
    print(f"[*] Génération des graphiques classiques...")


    # 01. Distribution globale de l'âge (Log scale)
    plt.figure()
    sns.histplot(df["aging_time"], bins=50, kde=True, log_scale=True, color="#3498db")
    plt.title("Distribution of Domain Age (Weaponization)")
    plt.xlabel("Aging Time (days, log scale)")
    plt.ylabel("Number of domains")
    plt.savefig(out_dir / "dist_age_log.png", dpi=300, bbox_inches='tight')
    plt.close()

    # 02. CDF du Temps de Vieillissement (Échelle Log)
    df_valid_age = df[df["aging_time"] > 0]
    plt.figure()
    sns.ecdfplot(data=df_valid_age, x="aging_time", color="#e74c3c")
    plt.title("CDF of Domain Aging Time")
    plt.xlabel("Aging Time (days, log)")
    plt.ylabel("Cumulative Proportion")
    plt.xscale('log')
    plt.savefig(out_dir / "cdf_age_log.png", dpi=300, bbox_inches='tight')
    plt.close()

    # 03. Délai de Mise à Jour WHOIS vs Âge (Carte de Densité Hexbin)
    df_updates = df[(df["update_delay"].notna()) & (df["update_delay"] >= 0)].copy()
    if not df_updates.empty:
        plt.figure(figsize=(10, 6))
        plt.hexbin(df_updates["aging_time"], df_updates["update_delay"], gridsize=40, cmap='Purples', xscale='log', yscale='symlog', mincnt=1, bins='log')
        plt.colorbar(label='log10(Number of domains)')
        plt.title("WHOIS Update Delay vs Age")
        plt.xlabel("Aging Time (days)")
        plt.ylabel("Update Delay (days before attack)")
        plt.axhline(0, color='red', linestyle='--', alpha=0.5)
        plt.tight_layout()
        plt.savefig(out_dir / "maj_whois_vs_age.png", dpi=300)
        plt.close()

    # 04. Délai de MAJ pour les 'Sleepers' (>180j)
    old_domains = df_updates[df_updates["aging_time"] > 180]
    if len(old_domains) > 0:
        plt.figure()
        sns.histplot(old_domains["update_delay"], bins=50, kde=True, color="#2ecc71")
        plt.title("Update Delay for Incubated Domains (>180d)")
        plt.xlabel("Update Delay (days before attack)")
        plt.ylabel("Number of domains")
        plt.xlim(0, 400)
        plt.savefig(out_dir / "dist_mises_a_jour_incubation.png", dpi=300, bbox_inches='tight')
        plt.close()

    # 05. Stratégies de Vieillissement selon le Top 15 Registrars (Noms réels)
    top_registrars_named = df[df["iana_id"] != "None"]["registrar_name"].value_counts().nlargest(15).index.tolist()
    df_registrars_named = df[df["registrar_name"].isin(top_registrars_named)]
    plt.figure(figsize=(14, 8))
    sns.boxplot(data=df_registrars_named, x="registrar_name", y="aging_time", order=top_registrars_named, palette="viridis")
    plt.yscale("log")
    plt.title("Aging Strategies by Registrar (Top 15)")
    plt.xlabel("Registrar")
    plt.ylabel("Aging Time (days, log scale)")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig(out_dir / "vieillissement_par_registrar.png", dpi=300, bbox_inches='tight')
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
        plt.title("Aging Time by Targeted Brand")
        plt.xlabel("Impersonated Brand")
        plt.ylabel("Aging Time (days, log scale)")
        plt.xticks(rotation=45)
        plt.legend(["Median Age", "90th Percentile Age"])
        plt.tight_layout()
        plt.savefig(out_dir / "vieillissement_par_marque.png", dpi=300, bbox_inches='tight')
        plt.close()

    # 07. Évolution Annuelle de l'Âge Médian
    yearly_median = df.groupby("year")["aging_time"].median().reset_index()
    yearly_counts = df.groupby("year").size()
    valid_years = yearly_counts[yearly_counts > 0].index
    yearly_median = yearly_median[yearly_median["year"].isin(valid_years)]
    if len(yearly_median) > 0:
        plt.figure()
        sns.lineplot(data=yearly_median, x="year", y="aging_time", marker="s", color="#c0392b", linewidth=2.5)
        plt.title("Evolution of Median Age (By Year)")
        plt.xlabel("Year of Attack (Discovery)")
        plt.ylabel("Median Aging Time (days)")
        min_year = int(yearly_median["year"].min())
        max_year = int(yearly_median["year"].max())
        plt.xticks(range(min_year, max_year + 1))
        plt.savefig(out_dir / "tendance_age_median_annuel.png", dpi=300, bbox_inches='tight')
        plt.close()

    # 08. Frise Pré-Militarisation
    if len(sample_timeline) > 0:
        plt.figure(figsize=(10, 6))
        for i, row in enumerate(sample_timeline):
            y = i
            ev = row["events"]
            plt.plot([ev["cd"], ev["discovery"]], [y, y], color="grey", alpha=0.3, zorder=1)
            plt.scatter(ev["cd"], y, color="#2c3e50", marker="s", s=80, label="Creation" if i==0 else "", zorder=2)
            plt.scatter(ev["discovery"], y, color="#c0392b", marker="X", s=120, label="Discovery" if i==0 else "", zorder=2)
            if ev.get("ip_change"):
                plt.scatter(ev["ip_change"], y, color="#27ae60", marker="^", s=100, label="IP Change (<7d)" if i==0 else "", zorder=3)
            if ev.get("html_change"):
                plt.scatter(ev["html_change"], y, color="#f39c12", marker="v", s=100, label="HTML Change (<7d)" if i==0 else "", zorder=3)
                
        plt.yticks(range(len(sample_timeline)), [f"Dom {i+1} (Age:{int(row['aging_time'])}d)" for i, row in enumerate(sample_timeline)])
        plt.title("Chronological Timeline of Pre-Weaponization Mutations")
        plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
        plt.tight_layout()
        plt.savefig(out_dir / "frise_pre_militarisation.png", dpi=300, bbox_inches='tight')
        plt.close()

    # 09. Classification des Stratégies
    plt.figure(figsize=(8, 6))
    ax = sns.countplot(data=df, x="aging_cluster", palette="magma")
    plt.title("Classification of Aging Strategies")
    plt.xlabel("Strategic Cluster")
    plt.ylabel("Number of Domains")
    for p in ax.patches:
        ax.annotate(f"{int(p.get_height())}", (p.get_x() + p.get_width() / 2., p.get_height()), ha='center', va='bottom')
    plt.savefig(out_dir / "clusters_strategies_vieillissement.png", dpi=300, bbox_inches='tight')
    plt.close()

    # 10. Espérance de Vie Opérationnelle (Survie) vs Âge (Carte de Densité Hexbin)
    df_surv = df.dropna(subset=["uptime_dur"]).copy()
    if not df_surv.empty:
        plt.figure(figsize=(10, 6))
        plt.hexbin(df_surv["aging_time"], df_surv["uptime_dur"], gridsize=40, cmap='Blues', xscale='symlog', yscale='symlog', mincnt=1, bins='log')
        plt.colorbar(label='log10(Number of domains)')
        plt.title("Operational Survival vs Domain Age")
        plt.xlabel("Aging Time (days)")
        plt.ylabel("Post-Attack Survival Duration (Uptime) (hours)")
        plt.tight_layout()
        plt.savefig(out_dir / "survie_vs_age.png", dpi=300)
        plt.close()

    # 11. Distribution de l'Écart avant Expiration
    df_exp = df.dropna(subset=["expiration_gap"])
    if len(df_exp) > 0:
        plt.figure()
        sns.histplot(df_exp["expiration_gap"], bins=100, kde=True, color="#d35400")
        plt.title("Gap between Discovery and Domain Expiration")
        plt.xlabel("Days between Discovery and Expiration")
        plt.ylabel("Number of domains")
        plt.xlim(-50, 750)
        plt.axvline(0, color='r', linestyle='--')
        plt.savefig(out_dir / "ecart_expiration_dist.png", dpi=300, bbox_inches='tight')
        plt.close()
        
    # 12. Tempo Opérationnel - Jour de l'Attaque (Weekend Gap)
    plt.figure(figsize=(10, 6))
    days_order = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    ax = sns.countplot(data=df, x="weekday", hue="strat_group", order=days_order, palette="coolwarm")
    plt.title("Weekend Gap Analysis by Strategy")
    plt.xlabel("Day of the week (Discovery)")
    plt.ylabel("Number of attacks")
    plt.xticks(rotation=45)
    # Remplacement des labels français de la légende de seaborn par de l'anglais
    handles, labels = ax.get_legend_handles_labels()
    new_labels = ["Incubation" if l == "Incubation" else "Direct Weaponization" for l in labels]
    plt.legend(handles, new_labels, title="Strategy")
    plt.tight_layout()
    plt.savefig(out_dir / "analyse_weekend_gap.png", dpi=300)
    plt.close()

    # 13. Crédibilité Lexicale - Longueur du Nom vs Âge
    plt.figure(figsize=(10, 6))
    sns.scatterplot(data=df, x="rd_len", y="aging_time", hue="aging_cluster", alpha=0.6, palette="viridis")
    plt.yscale("log")
    plt.axvline(10, color="red", linestyle="--", alpha=0.5, label="Credibility Threshold (10 chars)")
    plt.title("Relationship between Domain Length and Age")
    plt.xlabel("Root Domain Length (characters)")
    plt.ylabel("Incubation Time (days, log scale)")
    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.tight_layout()
    plt.savefig(out_dir / "longueur_domaine_vs_age.png", dpi=300)
    plt.close()

    # 14. Stratégie Extensions - Proportion Militarisation vs Incubation (Trié)
    top_tlds = df["tld"].value_counts().nlargest(10).index.tolist()
    if len(top_tlds) > 0:
        plt.figure(figsize=(12, 7))
        tld_dist_fixed = df[df["tld"].isin(top_tlds)].groupby(["tld", "strat_group"]).size().unstack().fillna(0)
        tld_dist_pct_fixed = tld_dist_fixed.div(tld_dist_fixed.sum(axis=1), axis=0) * 100
        
        if "Militarisation Directe" in tld_dist_pct_fixed.columns:
            tld_dist_pct_fixed = tld_dist_pct_fixed.sort_values(by="Militarisation Directe", ascending=False)
            
        tld_dist_pct_fixed.plot(kind="bar", stacked=True, color=["#e74c3c", "#3498db"], figsize=(12, 7))
        plt.title("Strategy Distribution by TLD")
        plt.ylabel("Percentage (%)")
        plt.xlabel("TLD (Top 10)")
        plt.axhline(50, color="gray", linestyle="--", alpha=0.5)
        # On force la traduction de la légende ici sans toucher aux données
        plt.legend(["Incubation", "Direct Weaponization"], title="Strategy")
        plt.tight_layout()
        plt.savefig(out_dir / "ratio_strategique_tld.png", dpi=300)
        plt.close()

    # 15. Saisonnalité - Volume Mensuel des Attaques
    plt.figure(figsize=(10, 6))
    monthly_data = df.groupby(["month", "strat_group"]).size().reset_index(name="count")
    ax = sns.lineplot(data=monthly_data, x="month", y="count", hue="strat_group", marker="o", linewidth=2.5)
    plt.title("Monthly Attack Seasonality")
    plt.xlabel("Month of the year")
    plt.ylabel("Number of attacks")
    plt.xticks(range(1, 13))
    # Traduction de la légende
    handles, labels = ax.get_legend_handles_labels()
    new_labels = ["Incubation" if l == "Incubation" else "Direct Weaponization" for l in labels]
    plt.legend(handles, new_labels, title="Strategy")
    plt.tight_layout()
    plt.savefig(out_dir / "saisonnalite_mensuelle.png", dpi=300)
    plt.close()

    # 16. ROI de l'Incubation - Survie Médiane post-attaque
    if not df_surv.empty:
        plt.figure(figsize=(10, 6))
        median_surv = df_surv.groupby("aging_cluster")["uptime_dur"].median().reset_index()
        sns.barplot(data=median_surv, x="aging_cluster", y="uptime_dur", palette="magma")
        plt.title("ROI of Incubation (Median Survival)")
        plt.ylabel("Median Survival Duration (Hours)")
        plt.xlabel("Strategic Age Cluster")
        plt.tight_layout()
        plt.savefig(out_dir / "roi_incubation_survie.png", dpi=300)
        plt.close()
    
    # 17. Ratio Stratégique des Registrars (Spécialisation)
    top_10_regs = df[df["iana_id"] != "None"]["registrar_name"].value_counts().nlargest(10).index.tolist()
    if len(top_10_regs) > 0:
        plt.figure(figsize=(12, 7))
        reg_dist = df[df["registrar_name"].isin(top_10_regs)].groupby(["registrar_name", "strat_group"]).size().unstack().fillna(0)
        reg_dist_pct = reg_dist.div(reg_dist.sum(axis=1), axis=0) * 100
        
        if "Militarisation Directe" in reg_dist_pct.columns:
            reg_dist_pct = reg_dist_pct.sort_values(by="Militarisation Directe", ascending=False)
            
        reg_dist_pct.plot(kind="bar", stacked=True, color=["#e74c3c", "#3498db"], figsize=(12, 7))
        plt.title("Strategic Specialization of Registrars")
        plt.ylabel("Percentage (%)")
        plt.xlabel("Registrar (Top 10)")
        plt.axhline(50, color="gray", linestyle="--", alpha=0.5)
        # On force la traduction de la légende
        plt.legend(["Incubation", "Direct Weaponization"], title="Strategy")
        plt.xticks(rotation=45, ha="right")
        plt.tight_layout()
        plt.savefig(out_dir / "ratio_strategique_registrars.png", dpi=300)
        plt.close()

    # 20. Évolution Temporelle Mensuelle Globale 
    plt.figure(figsize=(14, 6))
    monthly_evolution = df.groupby("year_month")["aging_time"].median().reset_index()
    monthly_evolution = monthly_evolution.sort_values("year_month")
    
    sns.lineplot(data=monthly_evolution, x="year_month", y="aging_time", marker="o", color="#8e44ad", linewidth=2)
    plt.title("Global Monthly Evolution of Median Age")
    plt.xlabel("Month of Discovery (Year-Month)")
    plt.ylabel("Median Aging Time (days)")
    plt.xticks(rotation=90, fontsize=8) 
    plt.tight_layout()
    plt.savefig(out_dir / "tendance_age_mensuelle_globale.png", dpi=300)
    plt.close()

    # 21. Évolution Mensuelle Fractionnée par Année
    unique_years = sorted(df["year"].unique())
    for y in unique_years:
        df_year = df[df["year"] == y]
        if len(df_year) > 100: 
            plt.figure(figsize=(10, 6))
            monthly_year_evol = df_year.groupby("month")["aging_time"].median().reset_index()
            sns.lineplot(data=monthly_year_evol, x="month", y="aging_time", marker="o", color="#c0392b", linewidth=2)
            plt.title(f"Monthly Evolution of Median Age for year {y}")
            plt.xlabel("Month")
            plt.ylabel("Median Aging Time (days)")
            plt.xticks(range(1, 13))
            plt.tight_layout()
            plt.savefig(out_dir / f"monthly_age_trend_{y}.png", dpi=300)
            plt.close()

    # 22 : Évolution des Stratégies de Vieillissement par Année (Échelle Étendue)
    plt.figure(figsize=(14, 7))
    sns.countplot(data=df, x="year", hue="extended_cluster", palette="magma")
    plt.title("Evolution of Aging Strategies (Extended Scale)")
    plt.xlabel("Year")
    plt.ylabel("Number of domains")
    plt.legend(title="Age Categories", bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.tight_layout()
    plt.savefig(out_dir / "strategies_vieillissement_annuel.png", dpi=300)
    plt.close()

    # 23 : Preuve du "Burn After Use" (Écart avant expiration par Stratégie)
    df_exp = df.dropna(subset=["expiration_gap"])
    # On filtre pour faire un beau zoom sur la dernière année de vie
    df_exp_zoom = df_exp[(df_exp["expiration_gap"] >= -50) & (df_exp["expiration_gap"] <= 400)]
    if not df_exp_zoom.empty:
        plt.figure(figsize=(10, 6))
        ax = sns.kdeplot(data=df_exp_zoom, x="expiration_gap", hue="strat_group", common_norm=False, fill=True, palette="Set1")
        plt.title("Evidence of Late Weaponization (Density)")
        plt.xlabel("Days Remaining before Expiration (during attack)")
        plt.ylabel("Distribution density")
        plt.axvline(0, color='red', linestyle='--', alpha=0.8, label='Expiration (0d)')
        plt.axvline(365, color='blue', linestyle='--', alpha=0.8, label='1 Year of validity (365d)')
        # On override la légende de seaborn pour afficher en anglais
        handles, labels = ax.get_legend_handles_labels()
        new_labels = ["Incubation" if l == "Incubation" else "Direct Weaponization" if l == "Militarisation Directe" else l for l in labels]
        plt.legend(handles, new_labels)
        plt.tight_layout()
        plt.savefig(out_dir / "militarisation_tardive_densite.png", dpi=300)
        plt.close()

    # Preuve de la Militarisation Tardive 
    if not df_exp_zoom.empty:
        # Ajout de sharex=False pour forcer l'affichage de l'axe des abscisses en haut
        fig, axes = plt.subplots(2, 1, figsize=(10, 8), sharex=False)
        
        sns.histplot(data=df_exp_zoom[df_exp_zoom["strat_group"] == "Militarisation Directe"], 
                     x="expiration_gap", color="#e74c3c", bins=50, kde=True, ax=axes[0])
        axes[0].set_title("Comparison: Direct Weaponization (Immediate Attack)")
        axes[0].set_ylabel("Number of domains")
        axes[0].set_xlabel("Days Remaining before Expiration (during attack)")
        axes[0].axvline(365, color='blue', linestyle='--', alpha=0.8, label='1 Year of validity (365d)')
        axes[0].set_xlim(-50, 400)
        axes[0].legend()
        
        sns.histplot(data=df_exp_zoom[df_exp_zoom["strat_group"] == "Incubation"], 
                     x="expiration_gap", color="#3498db", bins=50, kde=True, ax=axes[1])
        axes[1].set_title("Comparison: Late Weaponization (Incubation)")
        axes[1].set_xlabel("Days Remaining before Expiration (during attack)")
        axes[1].set_ylabel("Number of domains")
        axes[1].axvline(0, color='red', linestyle='--', alpha=0.8, label='Expiration (0d)')
        axes[1].set_xlim(-50, 400)
        axes[1].legend()
        
        plt.tight_layout()
        plt.savefig(out_dir / "militarisation_tardive_comparaison.png", dpi=300)
        plt.close()

    # 27 : Volume d'Attaques par Trimestre (Introduction)
    plt.figure(figsize=(12, 6))
    df_sorted_q = df.sort_values('quarter')
    sns.countplot(data=df_sorted_q, x="quarter", palette="viridis")
    plt.title("Evolution of Attack Volume by Quarter")
    plt.xlabel("Quarter (Year-Q)")
    plt.ylabel("Number of Malicious Domains Discovered")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(out_dir / "volume_attaques_trimestriel.png", dpi=300)
    plt.close()

    # 28 : Résistance aux Takedowns selon l'Âge du Domaine (Survie Old vs New)
    df_surv_clean = df.dropna(subset=["uptime_dur"])
    df_surv_clean = df_surv_clean[df_surv_clean["uptime_dur"] > 0]
    if not df_surv_clean.empty:
        plt.figure(figsize=(12, 7))
        sns.boxplot(data=df_surv_clean, x="extended_cluster", y="uptime_dur", palette="magma")
        plt.yscale("log")
        plt.title("Takedown Resistance by Age Category")
        plt.xlabel("Domain Age Category (from youngest to oldest)")
        plt.ylabel("Survival Duration before Takedown (Hours, log scale)")
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(out_dir / "resistance_takedown_par_age.png", dpi=300)
        plt.close()

    print(f"[*] Tous les graphiques ont été générés avec succès dans {out_dir}")

if __name__ == "__main__":
    main()