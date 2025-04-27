# Network Anomaly Detection using K-Means Clustering

This project implements a real-time network anomaly detection system using K-Means clustering on the NSL-KDD dataset. The system can classify network traffic as either normal or anomalous based on clustering patterns.

At the moment of writing this file, the model classifies the NSL-KDD test samples with 74% accuracy, is effective at identifying normal traffic but weak when it comes to catching anomalous patterns.

## Features

- Anomaly detection using K-Means clustering
- Feature selection and dimensionality reduction
- Performance evaluation and visualization
- Support for NSL-KDD dataset

## Requirements

- Python 3.8+
- Required packages (install using `pip install -r requirements.txt`):
  - numpy
  - pandas
  - scikit-learn
  - matplotlib
  - scipy

## Project Structure

```
.
├── main.py              # Main script to run the anomaly detection
├── data_processor.py    # Data loading and preprocessing
├── anomaly_detector.py  # K-Means based anomaly detection
├── visualizer.py        # Visualization utilities
├── requirements.txt     # Project dependencies
└── Data/               # Dataset directory
    ├── KDDTrain+.arff  # Training dataset
    └── KDDTest+.arff   # Test dataset
```

## Implementation Details

### Data Processing (`data_processor.py`)
- Handles loading of NSL-KDD dataset
- Preprocesses data including:
  - Feature scaling
  - Categorical variable encoding
  - Missing value handling

### Anomaly Detection (`anomaly_detector.py`)
- Implements K-Means clustering for anomaly detection
- Features:
  - Automatic cluster assignment (normal vs anomaly)
  - Feature selection using mutual information
  - PCA for dimensionality reduction
  - Two-cluster classification

### Visualization (`visualizer.py`)
- Provides visualization tools for:
  - Cluster distribution
  - Feature importance
  - Performance metrics

## Usage

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Place the NSL-KDD dataset files in the `Data` directory:
   - `KDDTrain+.arff`
   - `KDDTest+.arff`

3. Run the anomaly detection:
```bash
python main.py
```

## How It Works

1. **Data Loading and Preprocessing**
   - Loads NSL-KDD dataset
   - Preprocesses features (scaling, encoding)
   - Handles missing values

2. **Feature Selection and Dimensionality Reduction**
   - Selects top features using mutual information
   - Applies PCA to reduce dimensionality
   - Preserves 95% of variance

3. **Clustering and Classification**
   - Uses K-Means with 2 clusters
   - Automatically identifies normal traffic cluster
   - Classifies samples based on cluster assignment

4. **Evaluation and Visualization**
   - Calculates performance metrics
   - Visualizes cluster distribution
   - Shows feature importance

## Performance Metrics

The system evaluates performance using:
- Confusion Matrix
- Classification Report
- ROC AUC Score
- Average Precision Score

## Customization

You can modify the following parameters in `main.py`:
- `n_clusters`: Number of clusters (default: 2)
- `n_features`: Number of features to select (default: 15)
- `use_pca`: Whether to use PCA (default: True)

## Contributing

Feel free to contribute to this project by:
1. Forking the repository
2. Creating a feature branch
3. Submitting a pull request
