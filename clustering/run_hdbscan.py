import argparse
import hashlib
import warnings
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
CACHE_DIR = DATA_DIR / "cache"
SAMPLE_DIR = Path(__file__).parent.parent / "sample_data"


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------

def compute_cache_key(input_file: Path, n_features_hash: int, n_components: int) -> str:
    """
    Compute a short cache key based on:
    - Absolute path of the input file
    - File modification time (mtime) → invalidated if file changes
    - Vectorizer config (n_features_hash, n_components)
    """
    mtime = input_file.stat().st_mtime
    key_str = f"{input_file.resolve()}|mtime={mtime}|n_features_hash={n_features_hash}|n_components={n_components}"
    return hashlib.md5(key_str.encode()).hexdigest()[:16]


def load_cache(cache_key: str):
    """
    Load X_final and metadata DataFrame from cache if available.
    Returns (X_final, df_meta) or (None, None) if cache miss.
    """
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    vectors_path = CACHE_DIR / f"vectors_{cache_key}.npy"
    meta_path    = CACHE_DIR / f"meta_{cache_key}.parquet"

    if vectors_path.exists() and meta_path.exists():
        print(f"[+] Cache HIT (key={cache_key}). Loading vectors from disk...")
        X_final  = np.load(str(vectors_path))
        df_meta  = pd.read_parquet(str(meta_path))
        return X_final, df_meta

    return None, None


def save_cache(cache_key: str, X_final: np.ndarray, df_meta: pd.DataFrame):
    """Persist X_final and metadata to cache directory."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    vectors_path = CACHE_DIR / f"vectors_{cache_key}.npy"
    meta_path    = CACHE_DIR / f"meta_{cache_key}.parquet"

    np.save(str(vectors_path), X_final)
    df_meta.to_parquet(str(meta_path), index=False)
    print(f"[+] Vectors cached to {CACHE_DIR} (key={cache_key})")


# ---------------------------------------------------------------------------
# Processing helpers
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Main clustering pipeline
# ---------------------------------------------------------------------------

def run_clustering(input_file: Path, output_prefix: str, min_cluster_size: int, is_sample: bool,
                   batch_size: int = 50000, n_jobs: int = -1, n_features_hash: int = 16,
                   n_components: int = 128, no_cache: bool = False):
    print(f"[+] Processing {input_file} (batch={batch_size}, n_jobs={n_jobs}, "
          f"n_features_hash={n_features_hash}, svd_components={n_components})...")

    # --- Cache check ---
    cache_key = compute_cache_key(input_file, n_features_hash, n_components)
    ids_all = []
    meta_registrar, meta_tld, meta_asn, meta_creation = [], [], [], []
    X_final = None

    if not no_cache:
        X_final, df_meta = load_cache(cache_key)
        if X_final is not None:
            ids_all        = df_meta["id"].tolist()
            meta_registrar = df_meta["registrar_id"].tolist()
            meta_tld       = df_meta["tld"].tolist()
            meta_asn       = df_meta["asn"].tolist()
            meta_creation  = df_meta["creation_ts"].tolist()

    if X_final is None:
        # --- PASS 1: Count records ---
        print("[+] Pass 1: Counting records...")
        count = sum(1 for _ in parse_jsonl_stream(input_file))
        print(f"[+] Pass 1 complete. Total records: {count}")

        if count < min_cluster_size:
            print("[!] Not enough data for clustering.")
            return

        # --- PASS 2: Parallel extract + vectorize ---
        print(f"[+] Pass 2: Parallel vectorization (n_jobs={n_jobs})...")
        vectorizer = DomainVectorizer(n_features_hash=n_features_hash)
        stream_pass2 = parse_jsonl_stream(input_file)

        results = joblib.Parallel(n_jobs=n_jobs, prefer="threads", verbose=1)(
            joblib.delayed(process_batch)(batch_raw, vectorizer)
            for batch_raw in batched(stream_pass2, batch_size)
        )

        print("[+] Collecting results...")
        X_batches = []
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

        # SVD dimensionality reduction
        full_var = float(X_sparse.power(2).sum())
        if full_var == 0:
            print("[!] Warning: matrix has zero variance. Skipping TruncatedSVD — using raw sparse features (first 128 cols).")
            n_cols = min(128, X_sparse.shape[1])
            X_final = np.asarray(X_sparse[:, :n_cols].todense(), dtype=np.float32)
        else:
            effective_components = min(n_components, X_sparse.shape[0] - 1, X_sparse.shape[1] - 1)
            print(f"[+] Reducing dimensions with TruncatedSVD ({effective_components} components)...")
            svd = TruncatedSVD(n_components=effective_components, random_state=42)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", RuntimeWarning)
                X_final = svd.fit_transform(X_sparse)

        del X_sparse
        gc.collect()

        print(f"[+] Final Dense Matrix Shape: {X_final.shape}, Type: {X_final.dtype}")
        print(f"[+] Final Dense Matrix Size in RAM: {X_final.nbytes / 1024**3:.2f} GB")

        # --- Persist cache ---
        if not no_cache:
            df_meta = pd.DataFrame({
                "id": ids_all, "registrar_id": meta_registrar,
                "tld": meta_tld, "asn": meta_asn, "creation_ts": meta_creation
            })
            save_cache(cache_key, X_final, df_meta)

    # --- Clustering ---
    print(f"[+] Running HDBSCAN (min_cluster_size={min_cluster_size})...")
    clusterer = hdbscan.HDBSCAN(
        min_cluster_size=min_cluster_size,
        min_samples=1,
        core_dist_n_jobs=-1
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
    parser = argparse.ArgumentParser(description="Cluster malicious domains (Streaming + Parallel + Cache)")
    parser.add_argument("--input", type=str, help="Input JSONL file path")
    parser.add_argument("--sample", action="store_true", help="Use default sample file")
    parser.add_argument("--min-size", type=int, default=5, help="HDBSCAN min_cluster_size")
    parser.add_argument("--batch-size", type=int, default=50000, help="Batch size for processing")
    parser.add_argument("--n-jobs", type=int, default=-1, help="Number of parallel jobs (-1 = all CPUs)")
    parser.add_argument("--n-features-hash", type=int, default=16, help="FeatureHasher exponent (2^N features)")
    parser.add_argument("--svd-components", type=int, default=128, help="TruncatedSVD output dimensions")
    parser.add_argument("--no-cache", action="store_true", help="Force recompute even if cache exists")

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

    run_clustering(
        fpath, "malicious_campaigns_clusters", args.min_size, is_sample,
        args.batch_size, args.n_jobs, args.n_features_hash, args.svd_components, args.no_cache
    )


if __name__ == "__main__":
    main()
