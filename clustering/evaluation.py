import pandas as pd

def print_evaluation(csv_path: str):
    print("\n--- Clustering Evaluation ---")
    try:
        df = pd.read_csv(csv_path)
    except Exception as e:
        print(f"[!] Error reading results file for evaluation: {e}")
        return
        
    total_domains = len(df)
    print(f"Total domains evaluated: {total_domains}")
    
    if "cluster" not in df.columns:
        print("[!] Evaluation failed: 'cluster' column missing.")
        return
        
    labels = df["cluster"]
    n_clusters = labels.nunique()
    if -1 in labels.values:
        n_clusters -= 1
        
    n_noise = (labels == -1).sum()
    
    print(f"Total clusters (excluding noise): {n_clusters}")
    print(f"Noise domains: {n_noise} ({n_noise / total_domains * 100:.2f}%)")
    
    if n_clusters > 0:
        sizes = labels[labels != -1].value_counts()
        print(f"Largest cluster size: {sizes.max()}")
        print(f"Average cluster size: {sizes.mean():.2f}")
    
    print("-----------------------------\n")
