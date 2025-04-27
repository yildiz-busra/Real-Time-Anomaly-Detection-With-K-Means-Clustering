from data_processor import DataProcessor
from anomaly_detector import AnomalyDetector
from visualizer import Visualizer
import numpy as np
from sklearn.metrics import roc_auc_score, precision_recall_curve, average_precision_score
import matplotlib.pyplot as plt

def evaluate_model(X, y_true, y_pred, clusters, detector):
    """Evaluate model performance with multiple metrics"""
    # Calculate ROC AUC using cluster probabilities
    cluster_probs = np.zeros((len(X), 2))
    for i in range(len(X)):
        cluster_probs[i, clusters[i]] = 1
    roc_auc = roc_auc_score(y_true, cluster_probs[:, 1])
    print(f"\nROC AUC Score: {roc_auc:.4f}")
    
    # Calculate Average Precision
    ap_score = average_precision_score(y_true, cluster_probs[:, 1])
    print(f"Average Precision Score: {ap_score:.4f}")
    
    # Plot cluster distribution by class
    plt.figure(figsize=(10, 6))
    for cluster in range(2):
        mask = (clusters == cluster)
        plt.hist(y_true[mask], bins=[-0.5, 0.5, 1.5], alpha=0.7, 
                label=f'Cluster {cluster} ({"Normal" if cluster == detector.normal_cluster else "Anomaly"})')
    plt.xlabel('Class (0: Normal, 1: Anomaly)')
    plt.ylabel('Count')
    plt.title('Cluster Distribution by Class')
    plt.legend()
    plt.show()

def main():
    # Initialize components
    data_processor = DataProcessor()
    anomaly_detector = AnomalyDetector(
        n_clusters=2,  # Two clusters: normal and anomaly
        n_features=15,  # Select top 15 features
        use_pca=True  # Use PCA for dimensionality reduction
    )
    visualizer = Visualizer()
    
    # Load and preprocess training data
    print("Loading and preprocessing training data...")
    train_df = data_processor.load_arff_data("Data/KDDTrain+.arff")
    train_df = data_processor.preprocess_data(train_df)

    # Separate features and labels
    X_train = train_df.drop(columns=['attack_type', 'difficulty']).values
    y_train = (train_df['attack_type'] != 'normal').astype(int).values
    
    # Train the anomaly detector
    print("Training the anomaly detector...")
    anomaly_detector.fit(X_train, y_train)
    
    # Plot feature importance
    feature_scores = anomaly_detector.get_feature_scores()
    if feature_scores is not None:
        feature_names = [f'Feature {i}' for i in range(len(feature_scores))]
        visualizer.plot_feature_importance(feature_scores, feature_names)
    
    # Load and preprocess test data
    print("Loading and preprocessing test data...")
    test_df = data_processor.load_arff_data("Data/KDDTest+.arff")
    test_df = data_processor.preprocess_data(test_df)
    
    # Separate features and labels
    X_test = test_df.drop(columns=['attack_type', 'difficulty']).values
    y_test = (test_df['attack_type'] != 'normal').astype(int).values
    
    # Get predictions and clusters
    y_pred = anomaly_detector.predict(X_test)
    clusters = anomaly_detector.get_clusters(X_test)
    
    # Evaluate the model
    print("Evaluating the model...")
    anomaly_detector.evaluate(X_test, y_test)
    
    # Additional evaluation
    evaluate_model(X_test, y_test, y_pred, clusters, anomaly_detector)
    
    # Visualize results
    print("Visualizing results...")
    visualizer.plot_cluster_distribution(clusters)

if __name__ == "__main__":
    main()
