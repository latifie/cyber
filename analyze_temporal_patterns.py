import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os
import numpy as np

# Chemins
CLUSTERS_FILE = "/ssd/cyber/analysis_results/malicious_campaigns_clusters_full_20260314_145702.csv"
FEATURES_FILE = "/ssd/cyber/analysis_results/features_full_20260314.csv"
OUT_DIR = "/ssd/cyber/analysis_results/temporal_analysis"
os.makedirs(OUT_DIR, exist_ok=True)

print("Loading data...")
df_clusters = pd.read_csv(CLUSTERS_FILE)
df_features = pd.read_csv(FEATURES_FILE)

# On garde les colonnes utiles de features pour la jointure
# rd -> id (dans clusters)
df_features_sub = df_features[['rd', 'discovery_time', 'creation_date', 'uptime_dur_days']].drop_duplicates(subset=['rd'])

print("Joining datasets...")
df = pd.merge(df_clusters, df_features_sub, left_on='id', right_on='rd', how='inner')

# Nettoyage des dates
df['discovery_time'] = pd.to_datetime(df['discovery_time'], errors='coerce')
df['creation_date'] = pd.to_datetime(df['creation_date'], errors='coerce')

# Calcul de l'Aging (Discovery - Creation) en jours
df['aging_days'] = (df['discovery_time'] - df['creation_date']).dt.total_seconds() / 86400.0
# On ignore les valeurs absurdes (création après découverte ou aging > 10 ans)
df = df[(df['aging_days'] >= 0) & (df['aging_days'] < 3650)]

# Filtrage du bruit
df_valid = df[df['cluster'] != -1].copy()

# Calcul de la taille de chaque cluster
cluster_sizes = df_valid.groupby('cluster').size().rename('cluster_size')
df_valid = df_valid.merge(cluster_sizes, on='cluster')

# --- Catégorisation par taille ---
def categorize_size(s):
    if s <= 20: return "1. Small (10-20)"
    if s <= 50: return "2. Medium (21-50)"
    if s <= 200: return "3. Large (51-200)"
    return "4. Massive (201+)"

df_valid['size_category'] = df_valid['cluster_size'].apply(categorize_size)

# --- Agrégation par cluster (on veut une valeur par cluster pour ne pas pondérer par le nombre de domaines) ---
cluster_agg = df_valid.groupby('cluster').agg({
    'aging_days': 'median',
    'uptime_dur_days': 'median',
    'cluster_size': 'first',
    'size_category': 'first'
}).reset_index()

print("\nStatistiques par Catégorie de Taille :")
summary = cluster_agg.groupby('size_category').agg({
    'aging_days': ['mean', 'median', 'std'],
    'uptime_dur_days': ['mean', 'median', 'std'],
    'cluster': 'count'
})
print(summary)
summary.to_csv(f"{OUT_DIR}/temporal_summary_by_size.csv")

# --- Visualisations ---
plt.style.use('seaborn-v0_8-whitegrid')

# 1. Aging vs Size Category (Boxplot)
plt.figure(figsize=(12, 6))
sns.boxplot(x='size_category', y='aging_days', data=cluster_agg, palette='Blues', showfliers=False)
plt.title("Aging du domaine (Création -> Découverte) par Taille de Campagne")
plt.ylabel("Jours")
plt.xlabel("Taille de la Campagne")
plt.tight_layout()
plt.savefig(f"{OUT_DIR}/aging_vs_size_boxplot.png")

# 2. Takedown Duration vs Size Category (Boxplot)
plt.figure(figsize=(12, 6))
sns.boxplot(x='size_category', y='uptime_dur_days', data=cluster_agg, palette='Reds', showfliers=False)
plt.title("Durée de Vie de l'Attaque (Takedown) par Taille de Campagne")
plt.ylabel("Jours (Uptime)")
plt.xlabel("Taille de la Campagne")
plt.tight_layout()
plt.savefig(f"{OUT_DIR}/takedown_vs_size_boxplot.png")

# 3. Correlation Scatter (Aging vs Takedown)
plt.figure(figsize=(10, 8))
sns.scatterplot(x='aging_days', y='uptime_dur_days', hue='size_category', data=cluster_agg, alpha=0.6, s=20)
plt.xscale('log')
plt.yscale('log')
plt.title("Aging vs Takedown Duration (Échelle Log)")
plt.xlabel("Aging (jours)")
plt.ylabel("Takedown Duration (jours)")
plt.tight_layout()
plt.savefig(f"{OUT_DIR}/correlation_aging_takedown.png")

print(f"\nAnalyse terminée. Résultats sauvegardés dans {OUT_DIR}")
