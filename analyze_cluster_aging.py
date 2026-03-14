#!/usr/bin/env python3
"""
Analyse du vieillissement (aging) des domaines malicieux par cluster.

Croise le JSONL source (discovery_time) avec le CSV des clusters (creation_ts)
pour calculer l'aging = discovery_time - creation_ts par domaine, puis agrège
par cluster et par taille de campagne.

Génère 6 graphiques dans analysis_results/cluster_graphs/.
"""

import json
import os
import statistics
from datetime import datetime, timezone
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np
import pandas as pd
import seaborn as sns

# ─── Chemins ────────────────────────────────────────────────────────────────────
CLUSTER_CSV = Path("/ssd/cyber/analysis_results/malicious_campaigns_clusters_full_20260312_153239.csv")
JSONL_FILE = Path("/ssd/cyber/analysis_results/malicious_domains_takedown_whois_full_20260312_080250.jsonl")
OUT_DIR = Path("/ssd/cyber/analysis_results/cluster_graphs")
OUT_DIR.mkdir(parents=True, exist_ok=True)

# ─── Style ──────────────────────────────────────────────────────────────────────
sns.set_style("whitegrid")
plt.rcParams.update({
    "figure.figsize": (14, 8),
    "font.size": 12,
    "axes.titlesize": 14,
    "axes.labelsize": 12,
})

# ─── Catégories de taille ───────────────────────────────────────────────────────
SIZE_CATEGORIES = [
    ("Petits (2-5)", 2, 5),
    ("Moyens (6-20)", 6, 20),
    ("Grands (21-100)", 21, 100),
    ("Très grands (>100)", 101, float("inf")),
]


def categorize_size(n: int) -> str:
    """Attribue une catégorie de taille à un cluster."""
    for label, lo, hi in SIZE_CATEGORIES:
        if lo <= n <= hi:
            return label
    return "Inconnu"


def parse_datetime(dt_str: str):
    """Parse une date ISO avec gestion des erreurs – uniformise les timezones."""
    if not dt_str:
        return None
    try:
        if "T" in dt_str:
            dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        return datetime.strptime(dt_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        return None


def calculate_aging_days(discovery_time_str: str, creation_date_str: str):
    """Calcule le vieillissement en jours. Retourne None si impossible."""
    dt_disc = parse_datetime(discovery_time_str)
    dt_create = parse_datetime(creation_date_str)
    if not dt_disc or not dt_create:
        return None
    days = (dt_disc - dt_create).total_seconds() / 86400
    if days < 0 or days > 18250:  # > 50 ans = aberrant
        return None
    return days


# ═══════════════════════════════════════════════════════════════════════════════
# ÉTAPE 1: Charger le CSV des clusters
# ═══════════════════════════════════════════════════════════════════════════════
print("=" * 80)
print("ANALYSE DU VIEILLISSEMENT DES DOMAINES PAR CLUSTER")
print("=" * 80)

print("\n[1/4] Chargement du CSV des clusters...")
df_clusters = pd.read_csv(CLUSTER_CSV)
df_clusters = df_clusters[df_clusters["cluster"] != -1].copy()
df_clusters = df_clusters.drop_duplicates(subset=["id", "cluster"])
print(f"       → {len(df_clusters):,} domaines uniques dans {df_clusters['cluster'].nunique():,} clusters")

# Build lookup: domain_id → (cluster, creation_ts) — vectorized, no iterrows
domain_to_cluster = dict(zip(
    df_clusters["id"],
    zip(df_clusters["cluster"].astype(int), df_clusters["creation_ts"].astype(str))
))

# ═══════════════════════════════════════════════════════════════════════════════
# ÉTAPE 2: Streamer le JSONL pour extraire discovery_time
# ═══════════════════════════════════════════════════════════════════════════════
print(f"\n[2/4] Lecture du JSONL ({JSONL_FILE.name}, ~{JSONL_FILE.stat().st_size / 1e9:.1f} Go)...")
print("       Cela peut prendre quelques minutes...")

# Result: list of dicts with cluster, aging_days, discovery_time, size_category
records = []
matched = 0
total_read = 0

with JSONL_FILE.open("r", encoding="utf-8") as f:
    for line in f:
        total_read += 1
        if total_read % 50_000 == 0:
            print(f"       {total_read:>10,} lignes lues, {matched:>8,} domaines matchés...", end="\r")
        
        line = line.strip()
        if not line:
            continue
        
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        
        domain_id = rec.get("rd") or rec.get("fqdn")
        if not domain_id or domain_id not in domain_to_cluster:
            continue
        
        cluster_id, creation_ts = domain_to_cluster[domain_id]
        discovery_time = rec.get("discovery_time", "")
        
        if not discovery_time or not creation_ts:
            continue
        
        aging = calculate_aging_days(discovery_time, creation_ts)
        if aging is None:
            continue
        
        matched += 1
        records.append({
            "domain": domain_id,
            "cluster": cluster_id,
            "aging_days": aging,
            "discovery_time": discovery_time,
            "creation_ts": creation_ts,
        })

print(f"\n       → {total_read:,} lignes lues, {matched:,} domaines matchés avec aging valide")

# ═══════════════════════════════════════════════════════════════════════════════
# ÉTAPE 3: Agréger par cluster
# ═══════════════════════════════════════════════════════════════════════════════
print("\n[3/4] Agrégation par cluster...")

df = pd.DataFrame(records)

if df.empty:
    print("[!] Aucune donnée d'aging trouvée ! Vérifier les fichiers source.")
    exit(1)

# Per-cluster aggregation
cluster_stats = df.groupby("cluster").agg(
    aging_mean=("aging_days", "mean"),
    aging_median=("aging_days", "median"),
    aging_std=("aging_days", "std"),
    cluster_size=("domain", "nunique"),
    discovery_min=("discovery_time", "min"),
    discovery_max=("discovery_time", "max"),
).reset_index()

cluster_stats["aging_std"] = cluster_stats["aging_std"].fillna(0)
cluster_stats["size_category"] = cluster_stats["cluster_size"].apply(categorize_size)

# Order categories for plotting
cat_order = [c[0] for c in SIZE_CATEGORIES]
cluster_stats["size_category"] = pd.Categorical(
    cluster_stats["size_category"], categories=cat_order, ordered=True
)

print(f"       → {len(cluster_stats):,} clusters avec données d'aging")
print(f"\n       Résumé par catégorie de taille :")
for cat in cat_order:
    subset = cluster_stats[cluster_stats["size_category"] == cat]
    if len(subset) > 0:
        med = subset["aging_median"].median()
        print(f"         {cat:25s}: {len(subset):>5,} clusters, aging médian = {med:.1f} jours")

# ═══════════════════════════════════════════════════════════════════════════════
# ÉTAPE 4: Graphiques
# ═══════════════════════════════════════════════════════════════════════════════
print("\n[4/4] Génération des graphiques...")

# ─── Graphique 1: Scatter – Aging moyen vs Taille du cluster ────────────────
fig, ax = plt.subplots(figsize=(14, 8))
scatter = ax.scatter(
    cluster_stats["cluster_size"],
    cluster_stats["aging_mean"],
    c=cluster_stats["aging_mean"],
    cmap="RdYlGn_r",
    alpha=0.6,
    s=20,
    edgecolor="none",
)
ax.set_xscale("log")
ax.set_xlabel("Taille du cluster (nombre de domaines uniques)")
ax.set_ylabel("Aging moyen (jours)")
ax.set_title("Aging moyen vs Taille du cluster\n(chaque point = un cluster)")
plt.colorbar(scatter, ax=ax, label="Aging moyen (jours)")
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig(OUT_DIR / "aging_vs_cluster_size_scatter.png", dpi=200, bbox_inches="tight")
print("  [✓] aging_vs_cluster_size_scatter.png")
plt.close()

# ─── Graphique 2: Box plot – Aging par catégorie de taille ──────────────────
fig, ax = plt.subplots(figsize=(12, 7))
data_boxplot = []
labels_boxplot = []
for cat in cat_order:
    subset = cluster_stats[cluster_stats["size_category"] == cat]
    if len(subset) > 0:
        data_boxplot.append(subset["aging_median"].values)
        labels_boxplot.append(f"{cat}\n(n={len(subset)})")

bp = ax.boxplot(
    data_boxplot,
    labels=labels_boxplot,
    patch_artist=True,
    showfliers=True,
    flierprops={"markersize": 3, "alpha": 0.4},
)
colors = ["#4CAF50", "#FFC107", "#FF9800", "#F44336"]
for patch, color in zip(bp["boxes"], colors):
    patch.set_facecolor(color)
    patch.set_alpha(0.7)
ax.set_ylabel("Aging médian du cluster (jours)")
ax.set_title("Distribution de l'aging par catégorie de taille de campagne")
ax.grid(True, alpha=0.3, axis="y")
plt.tight_layout()
plt.savefig(OUT_DIR / "aging_by_size_category_boxplot.png", dpi=200, bbox_inches="tight")
print("  [✓] aging_by_size_category_boxplot.png")
plt.close()

# ─── Graphique 3: Évolution temporelle de l'aging ──────────────────────────
df["discovery_dt"] = pd.to_datetime(df["discovery_time"], errors="coerce")
df_temporal = df.dropna(subset=["discovery_dt"]).copy()
df_temporal["quarter"] = df_temporal["discovery_dt"].dt.to_period("Q")

temporal_stats = df_temporal.groupby("quarter").agg(
    aging_median=("aging_days", "median"),
    aging_mean=("aging_days", "mean"),
    count=("domain", "count"),
).reset_index()
temporal_stats["quarter_str"] = temporal_stats["quarter"].astype(str)

if len(temporal_stats) > 0:
    fig, ax1 = plt.subplots(figsize=(14, 7))
    
    x = range(len(temporal_stats))
    ax1.bar(x, temporal_stats["count"], alpha=0.3, color="steelblue", label="Nombre de domaines")
    ax1.set_ylabel("Nombre de domaines", color="steelblue")
    ax1.tick_params(axis="y", labelcolor="steelblue")
    
    ax2 = ax1.twinx()
    ax2.plot(x, temporal_stats["aging_median"], "o-", color="red", linewidth=2, label="Aging médian")
    ax2.plot(x, temporal_stats["aging_mean"], "s--", color="darkorange", linewidth=1.5, alpha=0.7, label="Aging moyen")
    ax2.set_ylabel("Aging (jours)", color="red")
    ax2.tick_params(axis="y", labelcolor="red")
    
    ax1.set_xticks(list(x))
    ax1.set_xticklabels(temporal_stats["quarter_str"], rotation=45, ha="right")
    ax1.set_xlabel("Trimestre")
    ax1.set_title("Évolution temporelle de l'aging des domaines malicieux")
    
    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc="upper left")
    
    plt.tight_layout()
    plt.savefig(OUT_DIR / "aging_temporal_evolution.png", dpi=200, bbox_inches="tight")
    print("  [✓] aging_temporal_evolution.png")
    plt.close()

# ─── Graphique 4: Heatmap – Aging par taille × période ─────────────────────
df_temporal["size_category"] = df_temporal["cluster"].map(
    cluster_stats.set_index("cluster")["size_category"]
)
df_temporal_valid = df_temporal.dropna(subset=["size_category"]).copy()

if len(df_temporal_valid) > 0:
    heatmap_data = df_temporal_valid.groupby(
        ["size_category", "quarter"]
    )["aging_days"].median().reset_index()
    
    heatmap_pivot = heatmap_data.pivot_table(
        index="size_category",
        columns="quarter",
        values="aging_days",
    )
    # Rename columns to string for display
    heatmap_pivot.columns = [str(c) for c in heatmap_pivot.columns]
    
    fig, ax = plt.subplots(figsize=(16, 6))
    sns.heatmap(
        heatmap_pivot,
        annot=True,
        fmt=".0f",
        cmap="YlOrRd",
        ax=ax,
        linewidths=0.5,
        cbar_kws={"label": "Aging médian (jours)"},
    )
    ax.set_title("Aging médian par taille de campagne × trimestre")
    ax.set_xlabel("Trimestre")
    ax.set_ylabel("Catégorie de taille")
    plt.tight_layout()
    plt.savefig(OUT_DIR / "aging_heatmap_size_period.png", dpi=200, bbox_inches="tight")
    print("  [✓] aging_heatmap_size_period.png")
    plt.close()

# ─── Graphique 5: Violin plot – Distribution par catégorie ─────────────────
# Use per-domain aging grouped by cluster size category
df["size_category"] = df["cluster"].map(
    cluster_stats.set_index("cluster")["size_category"]
)
df_violin = df.dropna(subset=["size_category"]).copy()

if len(df_violin) > 0:
    fig, ax = plt.subplots(figsize=(12, 7))
    
    # Cap aging at 365 days for readability
    df_violin["aging_capped"] = df_violin["aging_days"].clip(upper=365)
    
    sns.violinplot(
        data=df_violin,
        x="size_category",
        y="aging_capped",
        order=cat_order,
        palette=["#4CAF50", "#FFC107", "#FF9800", "#F44336"],
        inner="quartile",
        cut=0,
        ax=ax,
    )
    ax.set_xlabel("Catégorie de taille de campagne")
    ax.set_ylabel("Aging (jours, plafonné à 365)")
    ax.set_title("Distribution de l'aging par catégorie de taille de campagne\n(violin plot, par domaine)")
    ax.grid(True, alpha=0.3, axis="y")
    plt.tight_layout()
    plt.savefig(OUT_DIR / "aging_by_size_violin.png", dpi=200, bbox_inches="tight")
    print("  [✓] aging_by_size_violin.png")
    plt.close()

# ─── Graphique 6: Bar chart – Top 20 plus grands clusters ──────────────────
top20 = cluster_stats.nlargest(20, "cluster_size").sort_values("cluster_size", ascending=True)

if len(top20) > 0:
    fig, ax = plt.subplots(figsize=(12, 8))
    
    y_pos = range(len(top20))
    bars = ax.barh(
        y_pos,
        top20["aging_mean"],
        xerr=top20["aging_std"],
        color=plt.cm.RdYlGn_r(top20["aging_mean"] / top20["aging_mean"].max()),
        edgecolor="gray",
        alpha=0.8,
        capsize=3,
    )
    
    labels = [f"Cluster {c} (n={s})" for c, s in zip(top20["cluster"], top20["cluster_size"])]
    ax.set_yticks(list(y_pos))
    ax.set_yticklabels(labels)
    ax.set_xlabel("Aging moyen (jours) ± écart-type")
    ax.set_title("Aging moyen des 20 plus grandes campagnes")
    ax.grid(True, alpha=0.3, axis="x")
    plt.tight_layout()
    plt.savefig(OUT_DIR / "top20_clusters_aging.png", dpi=200, bbox_inches="tight")
    print("  [✓] top20_clusters_aging.png")
    plt.close()

# ═══════════════════════════════════════════════════════════════════════════════
# Résumé final
# ═══════════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("RÉSUMÉ")
print("=" * 80)
print(f"Domaines avec aging valide : {len(df):,}")
print(f"Clusters analysés          : {len(cluster_stats):,}")
print(f"Aging global médian        : {df['aging_days'].median():.1f} jours")
print(f"Aging global moyen         : {df['aging_days'].mean():.1f} jours")
print(f"\nGraphiques sauvegardés dans : {OUT_DIR}/")
print("=" * 80)
