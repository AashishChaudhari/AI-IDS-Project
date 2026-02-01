#!/usr/bin/env python3
"""
CIC-IDS2017 Preprocessor - Handles Large Dataset Efficiently
"""

import pandas as pd
import numpy as np
from pathlib import Path
from colorama import Fore, init
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
import pickle
import json

init(autoreset=True)

class CICIDS2017Preprocessor:
    """Process CIC-IDS2017 efficiently"""
    
    def __init__(self, sample_size=500000):
        self.sample_size = sample_size
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}CIC-IDS2017 PREPROCESSOR")
        if sample_size:
            print(f"{Fore.CYAN}Using {sample_size:,} samples")
        print(f"{Fore.CYAN}{'='*60}\n")
    
    def load_data(self):
        """Load CIC-IDS2017 data"""
        print(f"{Fore.YELLOW}Loading CIC-IDS2017 data...\n")
        
        data_dir = Path('data/raw/cicids2017')
        csv_files = sorted(data_dir.glob("*.csv"))
        
        if not csv_files:
            print(f"{Fore.RED}❌ No CSV files found in {data_dir}")
            exit(1)
        
        print(f"{Fore.CYAN}Found {len(csv_files)} CSV files:")
        for f in csv_files:
            size_mb = f.stat().st_size / (1024**2)
            print(f"  • {f.name}: {size_mb:.1f} MB")
        print()
        
        # Load all files
        dfs = []
        total_loaded = 0
        
        for csv_file in csv_files:
            print(f"{Fore.YELLOW}Loading {csv_file.name}...")
            
            try:
                df = pd.read_csv(csv_file, encoding='utf-8', on_bad_lines='skip')
            except:
                try:
                    df = pd.read_csv(csv_file, encoding='latin1', on_bad_lines='skip')
                except Exception as e:
                    print(f"{Fore.RED}  ✗ Failed to load: {e}")
                    continue
            
            # Clean column names
            df.columns = df.columns.str.strip()
            
            dfs.append(df)
            total_loaded += len(df)
            print(f"{Fore.GREEN}  ✓ Loaded {len(df):,} records (Total: {total_loaded:,})")
            
            if self.sample_size and total_loaded >= self.sample_size * 1.5:
                break
        
        # Combine
        print(f"\n{Fore.YELLOW}Combining datasets...")
        self.df = pd.concat(dfs, ignore_index=True)
        
        # Sample if needed
        if self.sample_size and len(self.df) > self.sample_size:
            print(f"{Fore.YELLOW}Sampling {self.sample_size:,} records...")
            self.df = self.df.sample(n=self.sample_size, random_state=42)
        
        print(f"{Fore.GREEN}✅ Total: {len(self.df):,} records, {len(self.df.columns)} columns\n")
    
    def clean_data(self):
        """Clean the dataset"""
        print(f"{Fore.YELLOW}Cleaning data...\n")
        
        # Find label column
        label_cols = [col for col in self.df.columns if 'label' in col.lower()]
        if not label_cols:
            print(f"{Fore.RED}❌ No label column found!")
            print(f"Available columns: {list(self.df.columns[:10])}")
            exit(1)
        
        self.label_col = label_cols[0]
        print(f"{Fore.CYAN}Label column: '{self.label_col}'")
        
        # Show distribution
        print(f"\n{Fore.CYAN}Attack distribution:")
        label_counts = self.df[self.label_col].value_counts()
        for label, count in label_counts.items():
            pct = (count / len(self.df)) * 100
            print(f"  {str(label)[:30]:30s}: {count:7,} ({pct:5.1f}%)")
        print()
        
        # Remove duplicates
        before = len(self.df)
        self.df = self.df.drop_duplicates()
        if before > len(self.df):
            print(f"  ✓ Removed {before - len(self.df):,} duplicates")
        
        # Get numerical columns only
        numerical_cols = self.df.select_dtypes(include=[np.number]).columns.tolist()
        
        # Handle infinite/missing
        for col in numerical_cols:
            # Infinite
            inf_mask = np.isinf(self.df[col])
            if inf_mask.any():
                self.df.loc[inf_mask, col] = self.df.loc[~inf_mask, col].max()
            
            # Missing
            if self.df[col].isnull().any():
                self.df[col].fillna(self.df[col].median(), inplace=True)
        
        # Keep only numerical + label
        cols_to_keep = numerical_cols + [self.label_col]
        self.df = self.df[cols_to_keep]
        
        print(f"{Fore.GREEN}✅ Cleaned: {self.df.shape}\n")
    
    def prepare_for_ml(self, test_size=0.2):
        """Prepare train/test"""
        print(f"{Fore.YELLOW}Preparing for ML...\n")
        
        X = self.df.drop(columns=[self.label_col]).values
        y_text = self.df[self.label_col].values
        
        # Encode labels
        y = self.label_encoder.fit_transform(y_text)
        
        print(f"{Fore.CYAN}Classes ({len(self.label_encoder.classes_)}):")
        for i, cls in enumerate(self.label_encoder.classes_):
            count = (y == i).sum()
            pct = (count / len(y)) * 100
            print(f"  {i}: {str(cls)[:25]:25s} {count:7,} ({pct:5.1f}%)")
        
        # Split
        print(f"\n{Fore.YELLOW}Splitting...")
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        
        # Scale
        print(f"{Fore.YELLOW}Scaling...")
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        feature_names = [c for c in self.df.columns if c != self.label_col]
        
        print(f"{Fore.GREEN}✅ Ready:")
        print(f"   Features: {len(feature_names)}")
        print(f"   Train: {len(X_train):,}")
        print(f"   Test: {len(X_test):,}\n")
        
        return X_train_scaled, X_test_scaled, y_train, y_test, feature_names
    
    def save_processed_data(self, X_train, X_test, y_train, y_test, 
                          features, output_dir='data/processed'):
        """Save processed data"""
        print(f"{Fore.YELLOW}Saving...\n")
        
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        
        np.save(out / 'X_train.npy', X_train)
        np.save(out / 'X_test.npy', X_test)
        np.save(out / 'y_train.npy', y_train)
        np.save(out / 'y_test.npy', y_test)
        
        with open(out / 'scaler.pkl', 'wb') as f:
            pickle.dump(self.scaler, f)
        
        with open(out / 'label_encoder.pkl', 'wb') as f:
            pickle.dump(self.label_encoder, f)
        
        with open(out / 'feature_names.json', 'w') as f:
            json.dump(features, f, indent=2)
        
        metadata = {
            'dataset': 'CIC-IDS2017',
            'n_features': len(features),
            'n_classes': len(self.label_encoder.classes_),
            'class_names': self.label_encoder.classes_.tolist(),
            'train_samples': len(X_train),
            'test_samples': len(X_test)
        }
        
        with open(out / 'metadata.json', 'w') as f:
            json.dump(metadata, f, indent=2)
        
        print(f"{Fore.GREEN}✅ Saved to: {out}\n")
    
    def run(self):
        """Run full pipeline"""
        self.load_data()
        self.clean_data()
        X_train, X_test, y_train, y_test, features = self.prepare_for_ml()
        self.save_processed_data(X_train, X_test, y_train, y_test, features)
        
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.GREEN}✅ PREPROCESSING COMPLETE!")
        print(f"{Fore.CYAN}{'='*60}\n")
        
        print(f"{Fore.YELLOW}Ready to train with {len(X_train):,} samples!")
        print(f"Expected accuracy: 88-95%!\n")


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--samples', type=int, default=500000)
    parser.add_argument('--full', action='store_true')
    args = parser.parse_args()
    
    size = None if args.full else args.samples
    preprocessor = CICIDS2017Preprocessor(sample_size=size)
    preprocessor.run()


if __name__ == "__main__":
    main()
