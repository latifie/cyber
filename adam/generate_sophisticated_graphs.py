#!/usr/bin/env python3
"""
Wave 2 Sophisticated Analysis Script
Optimized for 21GB+ files (Streaming / Low Memory)
Hypotheses: Weekend Gap, Lexical Length, TLD Costs, Seasonality, Survival ROI
"""

import json
import os
from pathlib import Path
from datetime import datetime, timezone
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np

def parse_date(date_str):
    if not date_str: return None
    try:
        if 'T' in date_str:
            dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
            else: dt = dt.astimezone(timezone.utc)
            return dt
        return datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except: return None

def get_tld(rd):
    if not rd or '.' not in rd: return "unknown"
    return rd.split('.')[-1].lower()

def main():
    sns.set_theme(style="whitegrid")
    base_dir = Path("/home/khalidad/cyber")
    out_dir = base_dir / "adam"
    out_dir.mkdir(parents=True, exist_ok=True)
    
    # Path to sample data (can be replaced by path to 21GB file)
    data_files = list((base_dir / "analysis_results").glob("malicious_domains_takedown_whois_sample_*.jsonl"))
    if not data_files:
        print("[!] No data files found.")
        return
    latest_file = sorted(data_files)[-1]
    
    print(f"[*] Processing: {latest_file}")
    
    extracted_data = []
    
    # MEMORY OPTIMIZED STREAMING
    with open(latest_file, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                rec = json.loads(line)
            except: continue
            
            discovery = parse_date(rec.get("discovery_time"))
            whois = rec.get("whois_bd") or {}
            cd = parse_date(whois.get("cd"))
            
            if not discovery or not cd: continue
            
            aging_time = (discovery - cd).total_seconds() / 86400
            if aging_time < 0 or aging_time > 15000: continue
            
            # Identify Clusters
            cluster = "Sleeper (>30j)"
            if aging_time <= 1: cluster = "Immédiat (<1j)"
            elif aging_time <= 7: cluster = "Rapide (1-7j)"
            elif aging_time <= 30: cluster = "Moyen (7-30j)"
            
            rd = rec.get("rd", "")
            tld = get_tld(rd)
            
            takedown = rec.get("takedown", {})
            uptime_dur = takedown.get("uptime_dur")
            if uptime_dur is not None and uptime_dur < 0: uptime_dur = None
            
            extracted_data.append({
                "aging_time": aging_time,
                "cluster": cluster,
                "weekday": discovery.strftime("%A"), # Monday, Tuesday...
                "day_num": discovery.weekday(),      # 0 to 6
                "month": discovery.month,
                "rd_len": len(rd),
                "tld": tld,
                "uptime_dur": uptime_dur
            })

    df = pd.DataFrame(extracted_data)
    # Categorical optimization
    df["cluster"] = pd.Categorical(df["cluster"], categories=["Immédiat (<1j)", "Rapide (1-7j)", "Moyen (7-30j)", "Sleeper (>30j)"], ordered=True)
    
    print(f"[+] Loaded {len(df)} records.")

    # --- Hypothèse A: Weekend Gap & Tempo Opérationnel ---
    plt.figure(figsize=(10, 6))
    days_order = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    # We compare Sprinters (Rapid/Immediate) vs Sleepers
    df["strat_group"] = df["cluster"].apply(lambda x: "Sleeper" if "Sleeper" in str(x) else "Sprinter")
    ax = sns.countplot(data=df, x="weekday", hue="strat_group", order=days_order, palette="coolwarm")
    plt.title("Hyp. A: Tempo Opérationnel - Jour de l'Attaque (Sprinters vs Sleepers)")
    plt.xlabel("Jour de la semaine (Discovery)")
    plt.ylabel("Nombre d'attaques")
    plt.xticks(rotation=45)
    plt.legend(title="Type d'attaquant")
    plt.tight_layout()
    plt.savefig(out_dir / "soph_A_weekend_gap.png", dpi=300)
    plt.close()

    # --- Hypothèse B: Similarité lexicale (RD Length) ---
    plt.figure(figsize=(10, 6))
    sns.scatterplot(data=df, x="rd_len", y="aging_time", hue="cluster", alpha=0.6, palette="viridis")
    plt.yscale("log")
    plt.axvline(10, color="red", linestyle="--", alpha=0.5, label="Seuil Crédibilité (10 chars)")
    plt.title("Hyp. B: Crédibilité Lexicale - Longueur du RD vs Âge du Domaine")
    plt.xlabel("Longueur du Root Domain (caractères)")
    plt.ylabel("Temps d'incubation (jours, échelle log)")
    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.tight_layout()
    plt.savefig(out_dir / "soph_B_lexical_length.png", dpi=300)
    plt.close()

    # --- Hypothèse C: TLD Low-Cost Strategy (Top 10) ---
    top_tlds = df["tld"].value_counts().nlargest(10).index.tolist()
    plt.figure(figsize=(12, 7))
    tld_dist = df[df["tld"].isin(top_tlds)].groupby(["tld", "strat_group"]).size().unstack().fillna(0)
    tld_dist_pct = tld_dist.div(tld_dist.sum(axis=1), axis=0) * 100
    tld_dist_pct.plot(kind="bar", stacked=True, color=["#e74c3c", "#3498db"], figsize=(12, 7))
    plt.title("Hyp. C: Stratégie TLD - Proportion Sprinters vs Sleepers par Extension")
    plt.ylabel("Pourcentage (%)")
    plt.xlabel("TLD (Top 10)")
    plt.axhline(50, color="gray", linestyle="--", alpha=0.5)
    plt.legend(title="Stratégie")
    plt.tight_layout()
    plt.savefig(out_dir / "soph_C_tld_strategy.png", dpi=300)
    plt.close()

    # --- Hypothèse D: Saisonnalité et Opportunisme (Monthly) ---
    plt.figure(figsize=(10, 6))
    monthly_data = df.groupby(["month", "strat_group"]).size().reset_index(name="count")
    sns.lineplot(data=monthly_data, x="month", y="count", hue="strat_group", marker="o", linewidth=2.5)
    plt.title("Hyp. D: Saisonnalité - Volume Mensuel (Sprinters vs Sleepers)")
    plt.xlabel("Mois de l'attaque")
    plt.ylabel("Nombre d'attaques")
    plt.xticks(range(1, 13))
    plt.tight_layout()
    plt.savefig(out_dir / "soph_D_monthly_seasonality.png", dpi=300)
    plt.close()

    # --- Hypothèse E: ROI de Survie (Survival per Cluster) ---
    plt.figure(figsize=(10, 6))
    # Median survival dur for the 4 clusters
    survivors = df.dropna(subset=["uptime_dur"])
    if not survivors.empty:
        median_surv = survivors.groupby("cluster")["uptime_dur"].median().reset_index()
        sns.barplot(data=median_surv, x="cluster", y="uptime_dur", palette="magma")
        plt.title("Hyp. E: ROI de l'Incubation - Survie Médiane post-attaque par Cluster")
        plt.ylabel("Durée de Survie Médiane (Heures)")
        plt.xlabel("Cluster Stratégique d'Âge")
        plt.tight_layout()
        plt.savefig(out_dir / "soph_E_survival_roi.png", dpi=300)
        plt.close()

    print(f"[*] Done. Sophisticated graphs saved in {out_dir}")

if __name__ == "__main__":
    main()
