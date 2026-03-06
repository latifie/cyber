import argparse
import joblib
import pandas as pd
import hdbscan
import numpy as np
import scipy.sparse as sp
from sklearn.decomposition import TruncatedSVD
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


def process_batch(batch_raw, vectorizer):
    """
    Extract features and vectorize a single batch.
    Returns (X_sparse, ids, registrar_ids, tlds, asns, creation_ts_list).
    Designed to be called in parallel via joblib.
    """
    records = [extract_features(r) for r in batch_raw]
    df_batch = pd.DataFrame(records)

    ids = df_batch["id"].tolist()
    registrar_ids = df_batch["registrar_id"].tolist()
    tlds = df_batch["tld"].tolist()
    asns = df_batch["asn"].tolist()
    creation_ts_list = df_batch["creation_ts"].tolist()

    X_batch = vectorizer.transform(df_batch)
    return X_batch, ids, registrar_ids, tlds, asns, creation_ts_list


def run_clustering(input_file: Path, output_prefix: str, min_cluster_size: int, is_sample: bool,
                   batch_size: int = 50000, n_jobs: int = -1):
    print(f"[+] Processing {input_file} with batch size {batch_size}, n_jobs={n_jobs}...")

    vectorizer = DomainVectorizer(n_features_hash=16)

    # --- PASS 1: Count records ---
    print("[+] Pass 1: Counting records...")
    count = 0
    for _ in parse_jsonl_stream(input_file):
        count += 1
    print(f"[+] Pass 1 complete. Total records: {count}")

    if count < min_cluster_size:
        print("[!] Not enough data for clustering.")
        return

    # --- PASS 2: Parallel extract + vectorize ---
    print(f"[+] Pass 2: Parallel vectorization (n_jobs={n_jobs})...")

    stream_pass2 = parse_jsonl_stream(input_file)

    # Collect batches as a list so joblib can dispatch them
    # We use a generator to avoid loading everything in memory at once.
    # joblib Parallel with prefer="threads" avoids GIL issues for scipy sparse ops.
    results = joblib.Parallel(n_jobs=n_jobs, prefer="threads", verbose=1)(
        joblib.delayed(process_batch)(batch_raw, vectorizer)
        for batch_raw in batched(stream_pass2, batch_size)
    )

    print("[+] Collecting results...")
    X_batches = []
    ids_all = []
    meta_registrar = []
    meta_tld = []
    meta_asn = []
    meta_creation = []

    for X_batch, ids, registrar_ids, tlds, asns, creation_ts_list in results:
        X_batches.append(X_batch)
        ids_all.extend(ids)
        meta_registrar.extend(registrar_ids)
        meta_tld.extend(tlds)
        meta_asn.extend(asns)
        meta_creation.extend(creation_ts_list)

    del results
    gc.collect()

    print("[+] Stacking sparse vectors...")
    X_sparse = sp.vstack(X_batches, format='csr')
    del X_batches
    gc.collect()

    print(f"[+] Sparse Matrix Shape: {X_sparse.shape}")

    print("[+] Reducing dimensions with TruncatedSVD (128 components)...")
    svd = TruncatedSVD(n_components=128, random_state=42)
    X_final = svd.fit_transform(X_sparse)

    del X_sparse
    gc.collect()

    print(f"[+] Final Dense Matrix Shape: {X_final.shape}, Type: {X_final.dtype}")
    print(f"[+] Final Dense Matrix Size in RAM: {X_final.nbytes / 1024**3:.2f} GB")

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

    from clustering.evaluation import print_evaluation
    print_evaluation(out_csv)


def main():
    parser = argparse.ArgumentParser(description="Cluster malicious domains (Streaming + Parallel)")
    parser.add_argument("--input", type=str, help="Input JSONL file path")
    parser.add_argument("--sample", action="store_true", help="Use default sample file")
    parser.add_argument("--min-size", type=int, default=5, help="HDBSCAN min_cluster_size")
    parser.add_argument("--batch-size", type=int, default=50000, help="Batch size for processing")
    parser.add_argument("--n-jobs", type=int, default=-1, help="Number of parallel jobs (-1 = all CPUs)")

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

    run_clustering(fpath, "malicious_campaigns_clusters", args.min_size, is_sample,
                   args.batch_size, args.n_jobs)


if __name__ == "__main__":
    main()
