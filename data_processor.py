import numpy as np
import pandas as pd
from scipy.io.arff import loadarff
from sklearn.preprocessing import LabelEncoder, StandardScaler
import os

class DataProcessor:
    def __init__(self):
        self.label_encoder = LabelEncoder()
        self.scaler = StandardScaler()
        self.categorical_columns = None
        self.numerical_columns = None
        
    def load_arff_data(self, file_path):
        """Load ARFF file and convert to pandas DataFrame"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
            
        try:
            # Try loading the TXT file directly
            df = pd.read_csv(file_path.replace('.arff', '.txt'), header=None)
            
            # Add column names based on NSL-KDD dataset structure
            columns = [
                'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
                'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
                'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
                'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
                'num_access_files', 'num_outbound_cmds', 'is_host_login',
                'is_guest_login', 'count', 'srv_count', 'serror_rate',
                'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
                'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
                'dst_host_srv_count', 'dst_host_same_srv_rate',
                'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
                'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
                'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
                'dst_host_srv_rerror_rate', 'attack_type', 'difficulty'
            ]
            
            if len(df.columns) == len(columns):
                df.columns = columns
            else:
                # If column count doesn't match, use default column names
                df.columns = [f'feature_{i}' for i in range(len(df.columns)-2)] + ['attack_type', 'difficulty']
                
            return df
        except Exception as e:
            raise Exception(f"Failed to load data: {str(e)}")
    
    def preprocess_data(self, df):
        """Preprocess the data including encoding categorical variables and scaling numerical features"""
        # Identify categorical and numerical columns
        categorical_cols = ['protocol_type', 'service', 'flag']
        numerical_cols = [col for col in df.columns if col not in categorical_cols + ['attack_type', 'difficulty']]
        
        # Store column information
        self.categorical_columns = categorical_cols
        self.numerical_columns = numerical_cols
        
        # Encode categorical variables
        for col in categorical_cols:
            df[col] = self.label_encoder.fit_transform(df[col])
            
        # Scale numerical features
        if len(numerical_cols) > 0:
            df[numerical_cols] = self.scaler.fit_transform(df[numerical_cols])
            
        return df
    
    def transform_new_data(self, df):
        """Transform new data using the same preprocessing steps"""
        # Encode categorical variables
        for col in self.categorical_columns:
            df[col] = self.label_encoder.transform(df[col])
            
        # Scale numerical features
        if len(self.numerical_columns) > 0:
            df[self.numerical_columns] = self.scaler.transform(df[self.numerical_columns])
            
        return df 