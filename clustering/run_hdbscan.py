import argparse
import json
import joblib
import pandas as pd
import hdbscan
import numpy as np
import gc
from pathlib import Path
from datetime import datetime
from itertools import islice

# Local imports
import sys
sys.path.append(str(Path(__file__).parent.parent))

from clustering.feature_extraction import extract_features
from clustering.vectorization import DomainVectorizer
from common_utils import parse_jsonl_stream

DATA_DIR = Path(__file__).parent.parent / "analysis_results"
SAMPLE_DIR = Path(__file__).parent.parent / "sample_data"

def batched(iterable, n):
    """Batch data into lists of length n. The last batch may be shorter."""
    it = iter(iterable)
    while True:
        batch = list(islice(it, n))
        if not batch:
            return
        yield batch

def run_clustering(input_file: Path, output_prefix: str, min_cluster_size: int, is_sample: bool, batch_size: int = 50000):
    print(f"[+] Processing {input_file} with batch size {batch_size}...")
    
    vectorizer = DomainVectorizer(n_features_hash=16)
    
    # --- PASS 1: Partial Fit (Scaling) ---
    print("[+] Pass 1: Calculating statistics for scaling...")
    count = 0
    # Create a fresh iterator for Pass 1
    stream_pass1 = parse_jsonl_stream(input_file)
    
    for batch_raw in batched(stream_pass1, batch_size):
        # Extract features
        records = [extract_features(r) for r in batch_raw]
        df_batch = pd.DataFrame(records)
        
        # Partial fit
        vectorizer.partial_fit(df_batch)
        
        count += len(batch_raw)
        if count % (batch_size * 5) == 0:
            print(f"    Processed {count} records...")
            gc.collect()
            
    print(f"[+] Pass 1 complete. Total records: {count}")
    
    if count < min_cluster_size:
        print("[!] Not enough data for clustering.")
        return

    # --- PASS 2: Transform and Collect ---
    print("[+] Pass 2: Vectorizing and collecting matrix...")
    
    # We need to collect the final dense matrix and IDs
    # For 20GB of data, we might have millions of rows.
    # Appending to a list of arrays is efficient enough, then vstack once.
    
    X_batches = []
    ids_all = []
    
    # Metadata for evaluation
    meta_registrar = []
    meta_tld = []
    meta_asn = []
    meta_creation = []
    
    stream_pass2 = parse_jsonl_stream(input_file)
    
    for batch_raw in batched(stream_pass2, batch_size):
        records = [extract_features(r) for r in batch_raw]
        df_batch = pd.DataFrame(records)
        
        # Collect IDs and Metadata
        ids_all.extend(df_batch["id"].tolist())
        meta_registrar.extend(df_batch["registrar_id"].tolist())
        meta_tld.extend(df_batch["tld"].tolist())
        meta_asn.extend(df_batch["asn"].tolist())
        meta_creation.extend(df_batch["creation_ts"].tolist())
        
        # Transform to float32 numpy array
        X_batch = vectorizer.transform(df_batch)
        X_batches.append(X_batch)
        
        # Explicit delete to help GC
        del df_batch
        del records
        
    print("[+] Stacking vectors...")
    X_final = np.vstack(X_batches)
    del X_batches
    gc.collect()
    
    print(f"[+] Final Matrix Shape: {X_final.shape}, Type: {X_final.dtype}")
    print(f"[+] Matrix Size in RAM: {X_final.nbytes / 1024**3:.2f} GB")
    
    # --- Clustering ---
    print(f"[+] Running HDBSCAN (min_cluster_size={min_cluster_size}, metric=euclidean)...")
    clusterer = hdbscan.HDBSCAN(
        min_cluster_size=min_cluster_size,
        min_samples=1,
        core_dist_n_jobs=-1  # Use all cores
    )
    clusterer.fit(X_final)
    
    labels = clusterer.labels_
    n_clusters = len(set(labels)) - (1 if -1 in labels else 0)
    n_noise = list(labels).count(-1)
    
    print(f"[+] Clustering done. Found {n_clusters} clusters. {n_noise} noise points.")
    
    # --- Save Results ---
    print("[+] Saving results...")
    
    # Re-assemble a simple dataframe for CSV output
    # We cannot keep the original dataframe in memory, so we construct result from IDs and labels
    
    df_result = pd.DataFrame({
        "id": ids_all,
        "cluster": labels,
        "registrar_id": meta_registrar,
        "tld": meta_tld,
        "asn": meta_asn,
        "creation_ts": meta_creation
    })
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    mode_str = "sample" if is_sample else "full"
    out_csv = DATA_DIR / f"{output_prefix}_{mode_str}_{timestamp}.csv"
    
    DATA_DIR.mkdir(exist_ok=True)
    df_result.to_csv(out_csv, index=False)
    print(f"[+] Results saved to {out_csv}")
    
    # Evaluate immediately
    from clustering.evaluation import print_evaluation
    print_evaluation(out_csv)

def main():
    parser = argparse.ArgumentParser(description="Cluster malicious domains (Streaming Optimized)")
    parser.add_argument("--input", type=str, help="Input JSONL file path")
    parser.add_argument("--sample", action="store_true", help="Use default sample file")
    parser.add_argument("--min-size", type=int, default=5, help="HDBSCAN min_cluster_size")
    parser.add_argument("--batch-size", type=int, default=50000, help="Batch size for processing")
    
    args = parser.parse_args()
    
    if args.input:
        fpath = Path(args.input)
        is_sample = False
    elif args.sample:
        fpath = SAMPLE_DIR / "down_domains_malicious_sample.jsonl.zst"
        is_sample = True
    else:
        print("Please specify --input or --sample")
        return
        
    if not fpath.exists():
        print(f"File not found: {fpath}")
        return
        
    run_clustering(fpath, "malicious_campaigns_clusters", args.min_size, is_sample, args.batch_size)

if __name__ == "__main__":
    main()
