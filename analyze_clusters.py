import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os

RESULTS_FILE = "/ssd/cyber/analysis_results/malicious_campaigns_clusters_full_20260312_153239.csv"
OUT_DIR = "/ssd/cyber/analysis_results/cluster_graphs"
os.makedirs(OUT_DIR, exist_ok=True)

print("Loading CSV...")
df = pd.read_csv(RESULTS_FILE)
df_valid = df[df["cluster"] != -1].copy()

# Ensure we're plotting unique domains (to avoid 1237 duplicates skewing true campaign size)
df_unique = df_valid.drop_duplicates(subset=["id", "cluster"]).copy()

# 1. Top 10 Largest Unique Campaigns
cluster_counts = df_unique["cluster"].value_counts().head(10)

plt.figure(figsize=(12, 6))
sns.barplot(x=cluster_counts.index.astype(str), y=cluster_counts.values, palette="viridis")
plt.title("Top 10 Largest Phishing Campaigns (By Unique Domains)")
plt.xlabel("Cluster ID")
plt.ylabel("Number of Unique Domains")
plt.tight_layout()
plt.savefig(f"{OUT_DIR}/top_10_clusters.png")
print("[+] Saved top_10_clusters.png")

# 2. Deep Dive: Cluster 13334 (Largest real campaign)
largest_cluster_id = cluster_counts.index[0]
df_largest = df_unique[df_unique["cluster"] == largest_cluster_id]

# TLD Distribution for Cluster 13334
plt.figure(figsize=(10, 5))
tld_counts = df_largest["tld"].value_counts().head(10)
sns.barplot(x=tld_counts.index, y=tld_counts.values, palette="magma")
plt.title(f"TLD Distribution in Largest Campaign (Cluster {largest_cluster_id})")
plt.xlabel("TLD")
plt.ylabel("Count")
plt.tight_layout()
plt.savefig(f"{OUT_DIR}/cluster_{largest_cluster_id}_tlds.png")
print(f"[+] Saved cluster_{largest_cluster_id}_tlds.png")

# Timeline of creation dates for Cluster 13334
df_largest["creation_ts"] = pd.to_datetime(df_largest["creation_ts"], errors="coerce")
timeline_counts = df_largest.dropna(subset=["creation_ts"]).groupby(df_largest["creation_ts"].dt.date).size()

plt.figure(figsize=(12, 6))
plt.plot(timeline_counts.index, timeline_counts.values, marker="o", linestyle="-", color="red")
plt.title(f"Domain Registration Timeline for Largest Campaign (Cluster {largest_cluster_id})")
plt.xlabel("Registration Date")
plt.ylabel("Number of Domains Registered")
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig(f"{OUT_DIR}/cluster_{largest_cluster_id}_timeline.png")
print(f"[+] Saved cluster_{largest_cluster_id}_timeline.png")

# 3. Overall Noise vs Grouped Domains Pie Chart
plt.figure(figsize=(8, 8))
noise_count = len(df[df["cluster"] == -1])
grouped_count = len(df_valid)
plt.pie([grouped_count, noise_count], labels=["Grouped in Campaigns", "Uncorrelated Noise"], 
        autopct='%1.1f%%', colors=["#4CAF50", "#F44336"], startangle=90)
plt.title("Overall Clustering Result (All Records)")
plt.savefig(f"{OUT_DIR}/overall_clustering_ratio.png")
print("[+] Saved overall_clustering_ratio.png")

print(f"\nAll graphs saved to {OUT_DIR}/")
