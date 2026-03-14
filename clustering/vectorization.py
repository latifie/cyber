"""
vectorization.py — version enrichie
=====================================
DomainVectorizer v2 :
  - Intègre les features numériques normalisées (temporal_norm, uptime_dur_norm)
    en plus du FeatureHasher textuel existant.
  - Concatène une matrice sparse (hashed) avec des colonnes denses (numériques)
    pour former la représentation finale.
"""

import numpy as np
import pandas as pd
import scipy.sparse as sp
from sklearn.feature_extraction import FeatureHasher


class DomainVectorizer:
    def __init__(self, n_features_hash: int = 16):
        """
        n_features_hash : exposant (si <= 32, utilise 2^n). Ex: 16 → 65536 features hashées.
        """
        if n_features_hash <= 32:
            self.n_features = 2 ** n_features_hash
        else:
            self.n_features = n_features_hash

        self.hasher = FeatureHasher(n_features=self.n_features, input_type="string")

    def partial_fit(self, df: pd.DataFrame):
        """FeatureHasher est stateless — méthode maintenue pour compatibilité API."""
        pass

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        """
        Transforme le DataFrame en matrice numérique pour HDBSCAN.

        Combine :
          1. Features textuelles / catégorielles hashées (FeatureHasher sparse)
             → colonnes 'text_features', 'registrar_id', 'tld', 'asn'
          2. Features numériques denses normalisées [0,1] :
             → 'temporal_norm'  : delta discovery→création, clampé 30j
             → 'uptime_dur_norm': durée de vie de l'attaque normalisée
        """
        raw_features = []
        temporal_vals = []
        uptime_dur_vals = []

        for _, row in df.iterrows():
            feats = []

            # --- Catégorielles ---
            if pd.notna(row.get("registrar_id")) and row["registrar_id"] != -1:
                feats.append(f"reg_{int(row['registrar_id'])}")

            if pd.notna(row.get("tld")) and row["tld"]:
                feats.append(f"tld_{row['tld']}")

            if pd.notna(row.get("asn")) and row["asn"] != -1:
                feats.append(f"asn_{int(row['asn'])}")

            # --- Bag-of-tokens (trg, src, domain n-grams, IPs, html_title, URI path) ---
            text = row.get("text_features")
            if pd.notna(text) and text:
                feats.extend(str(text).split())

            raw_features.append(feats)

            # --- Numériques ---
            tnorm = row.get("temporal_norm")
            temporal_vals.append(
                float(tnorm) if pd.notna(tnorm) else 0.5  # 0.5 = valeur neutre
            )

            udur = row.get("uptime_dur_days")
            uptime_dur_vals.append(
                float(udur) if pd.notna(udur) else 0.0
            )

        # --- Partie sparse : FeatureHasher ---
        X_sparse = self.hasher.transform(raw_features).astype(np.float32)

        # --- Normalisation uptime_dur ---
        uptime_arr = np.array(uptime_dur_vals, dtype=np.float32)
        max_dur = uptime_arr.max()
        if max_dur > 0:
            uptime_arr = np.clip(uptime_arr / max_dur, 0, 1)
        # else: reste à 0

        # --- Colonnes denses ---
        temporal_arr = np.array(temporal_vals, dtype=np.float32).reshape(-1, 1)
        uptime_arr = uptime_arr.reshape(-1, 1)

        # Pondération : on multiplie par un poids pour équilibrer l'influence
        # des features numériques face aux ~65k colonnes hashées (après SVD c'est géré)
        TEMPORAL_WEIGHT = 2.0   # la date est un signal fort pour les campagnes
        UPTIME_WEIGHT = 1.0

        dense_cols = np.hstack([
            temporal_arr * TEMPORAL_WEIGHT,
            uptime_arr * UPTIME_WEIGHT,
        ])  # shape: (N, 2)

        # Concatène sparse + dense (via scipy hstack avec dense converti en sparse)
        X_dense_sparse = sp.csr_matrix(dense_cols)
        X_combined = sp.hstack([X_sparse, X_dense_sparse], format="csr")

        return X_combined
