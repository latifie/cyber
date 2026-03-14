import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os
import numpy as np

# Chemins des fichiers
RESULTS_FILE = "/ssd/cyber/analysis_results/malicious_campaigns_clusters_full_20260314_145702.csv"
OUT_DIR = "/ssd/cyber/analysis_results/cluster_graphs_v2"
os.makedirs(OUT_DIR, exist_ok=True)

print(f"Loading results from {RESULTS_FILE}...")
df = pd.read_csv(RESULTS_FILE)

# Filtrage du bruit (-1)
df_valid = df[df["cluster"] != -1].copy()
cluster_sizes = df_valid["cluster"].value_counts()

print(f"Clusters trouvés : {len(cluster_sizes)}")

# --- 1. Statistiques Descriptives ---
stats = cluster_sizes.describe(percentiles=[.25, .5, .75, .9, .95])
print("\nStatistiques des tailles de clusters :")
print(stats)

# Sauvegarde des stats dans un fichier texte
with open(f"{OUT_DIR}/cluster_stats.txt", "w") as f:
    f.write("Statistiques des tailles de clusters (campagnes) :\n")
    f.write(stats.to_string())

# --- 2. Nuage de points (Scatter Plot) de la distribution ---
# On va afficher chaque cluster par son index et sa taille
plt.figure(figsize=(12, 6))
sns.scatterplot(x=range(len(cluster_sizes)), y=sorted(cluster_sizes.values, reverse=True), 
                alpha=0.5, edgecolor=None, s=10)
plt.yscale('log') # Log scale car les tailles varient énormément
plt.title("Distribution des tailles de campagnes (Échelle Log)")
plt.xlabel("Campagnes (triées par taille)")
plt.ylabel("Nombre de domaines (log)")
plt.grid(True, which="both", ls="-", alpha=0.2)
plt.tight_layout()
plt.savefig(f"{OUT_DIR}/cluster_size_distribution_scatter.png")
print("[+] Saved cluster_size_distribution_scatter.png")

# --- 3. Boxplot & Violin Plot (Moyenne, Médiane, Quartiles) ---
plt.figure(figsize=(10, 8))
plt.subplot(2, 1, 1)
sns.boxplot(x=cluster_sizes.values, color="skyblue")
plt.title("Boxplot des tailles de clusters")
plt.xlabel("Nombre de domaines")

plt.subplot(2, 1, 2)
# On filtre les extrêmes pour le violin plot pour y voir quelque chose
sns.violinplot(x=cluster_sizes[cluster_sizes < cluster_sizes.quantile(0.95)].values, color="lightgreen")
plt.title("Violin Plot des tailles de clusters (95ème percentile)")
plt.xlabel("Nombre de domaines")

plt.tight_layout()
plt.savefig(f"{OUT_DIR}/cluster_stats_plots.png")
print("[+] Saved cluster_stats_plots.png")

# --- 4. Vue Globale : Ratio Bruit vs Groupé ---
plt.figure(figsize=(8, 8))
noise_count = len(df[df["cluster"] == -1])
grouped_count = len(df_valid)
plt.pie([grouped_count, noise_count], labels=[f"En Campagnes ({grouped_count:,})", f"Bruit ({noise_count:,})"], 
        autopct='%1.1f%%', colors=["#2ecc71", "#e74c3c"], startangle=90, explode=(0.05, 0))
plt.title("Ratio Global : Campagnes vs Bruit")
plt.savefig(f"{OUT_DIR}/global_ratio_pie.png")
print("[+] Saved global_ratio_pie.png")

# --- 5. Top 20 Clusters (Bar Chart) ---
plt.figure(figsize=(14, 7))
top_20 = cluster_sizes.head(20)
sns.barplot(x=top_20.index.astype(str), y=top_20.values, palette="rocket")
plt.title("Top 20 des plus grandes campagnes identifiées")
plt.xlabel("Cluster ID")
plt.ylabel("Nombre de domaines")
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig(f"{OUT_DIR}/top_20_clusters.png")
print("[+] Saved top_20_clusters.png")

print(f"\nToutes les visualisations sont dans : {OUT_DIR}")
