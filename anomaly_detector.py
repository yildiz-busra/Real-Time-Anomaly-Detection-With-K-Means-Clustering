import numpy as np
from sklearn.cluster import KMeans
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.feature_selection import SelectKBest, mutual_info_classif
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA

class AnomalyDetector:
    def __init__(self, n_clusters=2, n_features=15, use_pca=True):
        self.n_clusters = n_clusters
        self.n_features = n_features
        self.use_pca = use_pca
        self.kmeans = KMeans(n_clusters=n_clusters, max_iter=1000, random_state=42, n_init=10)
        self.feature_selector = SelectKBest(mutual_info_classif, k=n_features)
        self.scaler = StandardScaler()
        self.pca = PCA(n_components=0.95) if use_pca else None
        self.normal_cluster = None  # Will store which cluster represents normal traffic
        
    def fit(self, X, y=None):
        """Fit the K-means model and determine which cluster represents normal traffic"""
        # Scale the data first
        X_scaled = self.scaler.fit_transform(X)
        
        # Select important features
        if y is not None:
            X_selected = self.feature_selector.fit_transform(X_scaled, y)
            self.feature_scores = self.feature_selector.scores_
        else:
            X_selected = self.feature_selector.fit_transform(X_scaled)
            self.feature_scores = self.feature_selector.scores_
            
        # Apply PCA if enabled
        if self.use_pca:
            X_selected = self.pca.fit_transform(X_selected)
            print(f"Number of PCA components: {self.pca.n_components_}")
            
        # Fit K-means
        self.kmeans.fit(X_selected)
        
        # Determine which cluster represents normal traffic
        if y is not None:
            # Count normal samples in each cluster
            cluster_counts = {}
            for cluster in range(self.n_clusters):
                mask = (self.kmeans.labels_ == cluster)
                normal_count = np.sum(y[mask] == 0)  # Count normal samples in this cluster
                cluster_counts[cluster] = normal_count
            
            # The cluster with most normal samples is the normal cluster
            self.normal_cluster = max(cluster_counts.items(), key=lambda x: x[1])[0]
        else:
            # If no labels provided, assume cluster 0 is normal
            self.normal_cluster = 0
        
        # Store selected feature indices
        self.selected_features = self.feature_selector.get_support(indices=True)
        
        return self
        
    def predict(self, X):
        """Predict anomalies in the data using cluster assignments"""
        # Scale and select features
        X_scaled = self.scaler.transform(X)
        X_selected = X_scaled[:, self.selected_features]
        
        # Apply PCA if enabled
        if self.use_pca:
            X_selected = self.pca.transform(X_selected)
        
        # Get cluster assignments
        clusters = self.kmeans.predict(X_selected)
        
        # Return 1 for anomalies (non-normal cluster), 0 for normal
        return (clusters != self.normal_cluster).astype(int)
    
    def get_clusters(self, X):
        """Get cluster assignments for the data"""
        X_scaled = self.scaler.transform(X)
        X_selected = X_scaled[:, self.selected_features]
        
        if self.use_pca:
            X_selected = self.pca.transform(X_selected)
            
        return self.kmeans.predict(X_selected)
    
    def evaluate(self, X, y_true):
        """Evaluate the model performance"""
        y_pred = self.predict(X)
        print("Confusion Matrix:")
        print(confusion_matrix(y_true, y_pred))
        print("\nClassification Report:")
        print(classification_report(y_true, y_pred, target_names=['Normal', 'Anomaly']))
        
        # Print feature importance
        if hasattr(self, 'selected_features'):
            print("\nSelected Features:")
            for idx in self.selected_features:
                print(f"Feature {idx}")
                
    def get_feature_scores(self):
        """Get feature importance scores"""
        return self.feature_scores if hasattr(self, 'feature_scores') else None 