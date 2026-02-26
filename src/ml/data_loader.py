#!/usr/bin/env python3
"""
Data Loader for AI-IDS
Loads preprocessed data from data/processed/
"""

import numpy as np
import pickle
import json
from pathlib import Path
from colorama import Fore, init

init(autoreset=True)

class DataLoader:
    """Load preprocessed IDS data"""
    
    def __init__(self):
        self.data_dir = Path('data/processed')
        self.X_train = None
        self.X_test = None
        self.y_train = None
        self.y_test = None
        self.scaler = None
        self.label_encoder = None
        self.feature_names = None
        self.metadata = None
    
    def load_all(self):
        """Load all preprocessed data"""
        print(f"{Fore.YELLOW}Loading preprocessed data...")
        
        # Check if data exists
        if not (self.data_dir / 'X_train.npy').exists():
            print(f"{Fore.RED}❌ No preprocessed data found!")
            print(f"{Fore.YELLOW}Run preprocessing first:")
            print(f"  python src/ml/generate_synthetic_data.py")
            raise FileNotFoundError("Preprocessed data not found")
        
        # Load arrays
        self.X_train = np.load(self.data_dir / 'X_train.npy')
        self.X_test = np.load(self.data_dir / 'X_test.npy')
        self.y_train = np.load(self.data_dir / 'y_train.npy')
        self.y_test = np.load(self.data_dir / 'y_test.npy')
        
        # Load preprocessing objects
        with open(self.data_dir / 'scaler.pkl', 'rb') as f:
            self.scaler = pickle.load(f)
        
        with open(self.data_dir / 'label_encoder.pkl', 'rb') as f:
            self.label_encoder = pickle.load(f)
        
        with open(self.data_dir / 'feature_names.json', 'r') as f:
            self.feature_names = json.load(f)
        
        with open(self.data_dir / 'metadata.json', 'r') as f:
            self.metadata = json.load(f)
        
        print(f"{Fore.GREEN}✅ Loaded: {len(self.X_train):,} train, {len(self.X_test):,} test")
    
    def get_data(self):
        """Get train/test splits"""
        return self.X_train, self.X_test, self.y_train, self.y_test
    
    def get_class_names(self):
        """Get class names"""
        return np.array(self.metadata['class_names'])
    
    def get_feature_names(self):
        """Get feature names"""
        return self.feature_names
    
    def get_metadata(self):
        """Get metadata"""
        return self.metadata
