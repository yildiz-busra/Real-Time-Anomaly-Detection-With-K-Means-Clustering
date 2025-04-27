import matplotlib.pyplot as plt
import numpy as np

class Visualizer:
    @staticmethod
    def plot_anomalies(X, distances, threshold, clusters):
        """Plot the anomaly detection results"""
        plt.figure(figsize=(10, 6))
        plt.scatter(range(len(X)), distances, c=clusters, cmap='coolwarm', alpha=0.7)
        plt.axhline(threshold, color='red', linestyle='--', label='Anomaly Threshold')
        plt.title('Anomaly Detection in Network Traffic')
        plt.xlabel('Data Points')
        plt.ylabel('Distance from Cluster Center')
        plt.legend()
        plt.show()
        
    @staticmethod
    def plot_cluster_distribution(clusters):
        """Plot the distribution of clusters"""
        plt.figure(figsize=(8, 6))
        plt.hist(clusters, bins=len(np.unique(clusters)), alpha=0.7)
        plt.title('Cluster Distribution')
        plt.xlabel('Cluster')
        plt.ylabel('Count')
        plt.show()
        
    @staticmethod
    def plot_feature_importance(feature_scores, feature_names=None):
        """Plot feature importance scores"""
        plt.figure(figsize=(12, 6))
        if feature_names is None:
            feature_names = [f'Feature {i}' for i in range(len(feature_scores))]
        plt.bar(range(len(feature_scores)), feature_scores)
        plt.xticks(range(len(feature_scores)), feature_names, rotation=45, ha='right')
        plt.title('Feature Importance Scores')
        plt.xlabel('Features')
        plt.ylabel('Importance Score')
        plt.tight_layout()
        plt.show() 