import numpy as np
import pandas as pd
from sklearn.feature_extraction import FeatureHasher

class DomainVectorizer:
    def __init__(self, n_features_hash=16):
        """
        Initializes the vectorizer.
        If n_features_hash <= 32, it's assumed to be power of 2 (e.g., 16 -> 2^16 = 65536).
        Otherwise it is taken literally.
        """
        if n_features_hash <= 32:
            self.n_features = 2 ** n_features_hash
        else:
            self.n_features = n_features_hash
            
        self.hasher = FeatureHasher(n_features=self.n_features, input_type='string')
        
    def partial_fit(self, df: pd.DataFrame):
        """
        Updates internal statistics if necessary.
        FeatureHasher doesn't require fitting, but provided for API compatibility.
        """
        pass
        
    def transform(self, df: pd.DataFrame) -> np.ndarray:
        """
        Transforms the dataframe into a numerical matrix.
        Combines categorical features into hashed vectors.
        """
        raw_features = []
        for _, row in df.iterrows():
            feats = []
            
            # Categorical logic
            if pd.notna(row.get('registrar_id')) and row['registrar_id'] != -1:
                feats.append(f"reg_{int(row['registrar_id'])}")
                
            if pd.notna(row.get('tld')) and row['tld']:
                feats.append(f"tld_{row['tld']}")
                
            if pd.notna(row.get('asn')) and row['asn'] != -1:
                feats.append(f"asn_{int(row['asn'])}")
                
            # Text / Hashes 
            text = row.get('text_features')
            if pd.notna(text) and text:
                feats.extend(str(text).split())
                
            raw_features.append(feats)
            
        # Hash features to sparse matrix, then dense float32 array
        X = self.hasher.transform(raw_features).toarray().astype(np.float32)
        return X
