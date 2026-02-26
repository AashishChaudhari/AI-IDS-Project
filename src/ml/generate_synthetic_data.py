#!/usr/bin/env python3
"""
Generate Synthetic IDS Training Data
Creates realistic network traffic data matching CIC-IDS2017 schema
"""

import numpy as np
import pickle
import json
from pathlib import Path
from colorama import Fore, init
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split

init(autoreset=True)

def generate_synthetic_ids_data(n_samples=470000):
    """Generate synthetic IDS data with realistic patterns"""
    
    print(f"{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}SYNTHETIC IDS DATA GENERATOR")
    print(f"{Fore.CYAN}Generating {n_samples:,} samples")
    print(f"{Fore.CYAN}{'='*60}\n")
    
    np.random.seed(42)
    
    # Class distribution (realistic)
    class_names = ['BENIGN', 'Bot', 'DDoS', 'PortScan']
    class_probs = [0.786, 0.002, 0.110, 0.102]  # Matches CIC-IDS2017
    
    labels = np.random.choice(class_names, size=n_samples, p=class_probs)
    
    print(f"{Fore.YELLOW}Generating features for each attack type...\n")
    
    # 78 features matching your schema
    features = []
    
    for i, label in enumerate(labels):
        if i % 100000 == 0:
            print(f"{Fore.CYAN}  Generated {i:,} / {n_samples:,} samples...")
        
        if label == 'BENIGN':
            # Normal traffic
            sample = [
                np.random.choice([80, 443, 22, 21, 25]),  # Destination Port
                np.random.exponential(5000),  # Flow Duration
                np.random.poisson(10),  # Total Fwd Packets
                np.random.poisson(8),   # Total Backward Packets
                np.random.normal(1500, 500),  # Total Length of Fwd Packets
                np.random.normal(1200, 400),  # Total Length of Bwd Packets
                np.random.normal(200, 50),   # Fwd Packet Length Max
                np.random.normal(50, 20),    # Fwd Packet Length Min
                np.random.normal(120, 30),   # Fwd Packet Length Mean
                np.random.normal(30, 10),    # Fwd Packet Length Std
                np.random.normal(180, 40),   # Bwd Packet Length Max
                np.random.normal(40, 15),    # Bwd Packet Length Min
                np.random.normal(100, 25),   # Bwd Packet Length Mean
                np.random.normal(25, 8),     # Bwd Packet Length Std
                np.random.normal(300, 100),  # Flow Bytes/s
                np.random.normal(3, 1),      # Flow Packets/s
                np.random.exponential(100),  # Flow IAT Mean
                np.random.exponential(50),   # Flow IAT Std
                np.random.exponential(200),  # Flow IAT Max
                np.random.exponential(10),   # Flow IAT Min
                np.random.exponential(500),  # Fwd IAT Total
                np.random.exponential(80),   # Fwd IAT Mean
                np.random.exponential(40),   # Fwd IAT Std
                np.random.exponential(150),  # Fwd IAT Max
                np.random.exponential(8),    # Fwd IAT Min
                np.random.exponential(400),  # Bwd IAT Total
                np.random.exponential(70),   # Bwd IAT Mean
                np.random.exponential(35),   # Bwd IAT Std
                np.random.exponential(140),  # Bwd IAT Max
                np.random.exponential(7),    # Bwd IAT Min
                np.random.poisson(1),        # Fwd PSH Flags
                np.random.poisson(1),        # Bwd PSH Flags
                0,  # Fwd URG Flags
                0,  # Bwd URG Flags
                np.random.normal(40, 10),    # Fwd Header Length
                np.random.normal(40, 10),    # Bwd Header Length
                np.random.normal(2, 0.5),    # Fwd Packets/s
                np.random.normal(1.5, 0.4),  # Bwd Packets/s
                np.random.normal(40, 15),    # Min Packet Length
                np.random.normal(200, 50),   # Max Packet Length
                np.random.normal(120, 30),   # Packet Length Mean
                np.random.normal(50, 15),    # Packet Length Std
                np.random.normal(2500, 500), # Packet Length Variance
                np.random.poisson(1),        # FIN Flag Count
                np.random.poisson(1),        # SYN Flag Count
                0,  # RST Flag Count
                np.random.poisson(2),        # PSH Flag Count
                np.random.poisson(15),       # ACK Flag Count
                0,  # URG Flag Count
                0,  # CWE Flag Count
                0,  # ECE Flag Count
                np.random.normal(0.8, 0.2),  # Down/Up Ratio
                np.random.normal(110, 25),   # Average Packet Size
                np.random.normal(120, 30),   # Avg Fwd Segment Size
                np.random.normal(100, 25),   # Avg Bwd Segment Size
                np.random.normal(40, 10),    # Fwd Header Length.1
                0,  # Fwd Avg Bytes/Bulk
                0,  # Fwd Avg Packets/Bulk
                0,  # Fwd Avg Bulk Rate
                0,  # Bwd Avg Bytes/Bulk
                0,  # Bwd Avg Packets/Bulk
                0,  # Bwd Avg Bulk Rate
                np.random.poisson(10),       # Subflow Fwd Packets
                np.random.normal(1500, 400), # Subflow Fwd Bytes
                np.random.poisson(8),        # Subflow Bwd Packets
                np.random.normal(1200, 300), # Subflow Bwd Bytes
                np.random.choice([8192, 16384, 32768]),  # Init_Win_bytes_forward
                np.random.choice([8192, 16384, 32768]),  # Init_Win_bytes_backward
                np.random.poisson(8),        # act_data_pkt_fwd
                np.random.normal(32, 10),    # min_seg_size_forward
                np.random.exponential(1000), # Active Mean
                np.random.exponential(500),  # Active Std
                np.random.exponential(2000), # Active Max
                np.random.exponential(100),  # Active Min
                np.random.exponential(5000), # Idle Mean
                np.random.exponential(2000), # Idle Std
                np.random.exponential(10000),# Idle Max
                np.random.exponential(500),  # Idle Min
            ]
            
        elif label == 'DDoS':
            # DDoS: High packet rate, similar sizes
            sample = [
                np.random.choice([80, 443]),  # Target common ports
                np.random.exponential(10000),
                np.random.poisson(500),  # VERY high forward packets
                np.random.poisson(5),    # Few backward
                np.random.normal(30000, 5000),  # High total bytes
                np.random.normal(300, 100),
                np.random.normal(80, 10),   # Small, uniform packets
                np.random.normal(60, 5),
                np.random.normal(70, 8),
                np.random.normal(10, 3),    # Low variance
                np.random.normal(100, 20),
                np.random.normal(40, 10),
                np.random.normal(70, 15),
                np.random.normal(15, 5),
                np.random.normal(3000, 500),  # HIGH bytes/s
                np.random.normal(50, 10),     # HIGH packets/s
                np.random.exponential(10),    # LOW inter-arrival time
                np.random.exponential(5),
                np.random.exponential(20),
                np.random.exponential(1),
                np.random.exponential(50),
                np.random.exponential(5),
                np.random.exponential(3),
                np.random.exponential(10),
                np.random.exponential(0.5),
                np.random.exponential(200),
                np.random.exponential(40),
                np.random.exponential(20),
                np.random.exponential(80),
                np.random.exponential(5),
                0, 0, 0, 0,
                np.random.normal(40, 5),
                np.random.normal(40, 5),
                np.random.normal(40, 8),
                np.random.normal(0.5, 0.2),
                np.random.normal(60, 10),
                np.random.normal(80, 10),
                np.random.normal(70, 10),
                np.random.normal(10, 3),
                np.random.normal(100, 30),
                0,
                np.random.poisson(300),  # Many SYN flags
                0,
                0,
                np.random.poisson(400),
                0, 0, 0,
                np.random.normal(0.01, 0.005),  # Very low down/up ratio
                np.random.normal(70, 10),
                np.random.normal(70, 10),
                np.random.normal(70, 15),
                np.random.normal(40, 5),
                0, 0, 0, 0, 0, 0,
                np.random.poisson(500),
                np.random.normal(30000, 5000),
                np.random.poisson(5),
                np.random.normal(300, 100),
                np.random.choice([1024, 2048]),
                np.random.choice([1024, 2048]),
                np.random.poisson(10),
                np.random.normal(40, 5),
                np.random.exponential(100),
                np.random.exponential(50),
                np.random.exponential(200),
                np.random.exponential(10),
                np.random.exponential(500),
                np.random.exponential(200),
                np.random.exponential(1000),
                np.random.exponential(50),
            ]
            
        elif label == 'PortScan':
            # Port Scan: Many different ports, low bytes
            sample = [
                np.random.randint(1, 65535),  # RANDOM ports
                np.random.exponential(1000),
                np.random.poisson(3),   # Few packets
                np.random.poisson(1),
                np.random.normal(200, 50),   # Low bytes
                np.random.normal(100, 30),
                np.random.normal(80, 20),
                np.random.normal(50, 15),
                np.random.normal(65, 15),
                np.random.normal(15, 5),
                np.random.normal(80, 20),
                np.random.normal(40, 10),
                np.random.normal(60, 15),
                np.random.normal(15, 5),
                np.random.normal(100, 50),
                np.random.normal(2, 1),
                np.random.exponential(50),
                np.random.exponential(20),
                np.random.exponential(100),
                np.random.exponential(5),
                np.random.exponential(100),
                np.random.exponential(30),
                np.random.exponential(15),
                np.random.exponential(60),
                np.random.exponential(3),
                np.random.exponential(80),
                np.random.exponential(25),
                np.random.exponential(12),
                np.random.exponential(50),
                np.random.exponential(2),
                0, 0, 0, 0,
                np.random.normal(40, 5),
                np.random.normal(40, 5),
                np.random.normal(1, 0.3),
                np.random.normal(0.3, 0.1),
                np.random.normal(50, 10),
                np.random.normal(80, 15),
                np.random.normal(65, 12),
                np.random.normal(15, 5),
                np.random.normal(225, 50),
                0,
                np.random.poisson(2),  # SYN flags
                np.random.poisson(1),  # RST flags (port closed)
                0,
                np.random.poisson(1),
                0, 0, 0,
                np.random.normal(0.3, 0.1),
                np.random.normal(60, 12),
                np.random.normal(65, 15),
                np.random.normal(55, 13),
                np.random.normal(40, 5),
                0, 0, 0, 0, 0, 0,
                np.random.poisson(3),
                np.random.normal(200, 50),
                np.random.poisson(1),
                np.random.normal(100, 30),
                np.random.choice([1024, 2048, 4096]),
                np.random.choice([1024, 2048]),
                np.random.poisson(2),
                np.random.normal(40, 5),
                np.random.exponential(500),
                np.random.exponential(200),
                np.random.exponential(1000),
                np.random.exponential(50),
                np.random.exponential(2000),
                np.random.exponential(1000),
                np.random.exponential(5000),
                np.random.exponential(200),
            ]
            
        else:  # Bot
            # Botnet: Periodic, predictable patterns
            sample = [
                np.random.choice([80, 443, 8080]),
                np.random.normal(20000, 5000),
                np.random.poisson(30),
                np.random.poisson(25),
                np.random.normal(3000, 500),
                np.random.normal(2500, 400),
                np.random.normal(120, 20),
                np.random.normal(80, 15),
                np.random.normal(100, 18),
                np.random.normal(20, 5),
                np.random.normal(110, 20),
                np.random.normal(70, 15),
                np.random.normal(95, 17),
                np.random.normal(18, 5),
                np.random.normal(250, 50),
                np.random.normal(2.5, 0.5),
                np.random.normal(800, 100),   # VERY regular IAT
                np.random.normal(50, 10),     # Low variance
                np.random.normal(900, 120),
                np.random.normal(700, 90),
                np.random.normal(12000, 2000),
                np.random.normal(800, 100),
                np.random.normal(50, 10),
                np.random.normal(900, 120),
                np.random.normal(700, 90),
                np.random.normal(10000, 1800),
                np.random.normal(750, 90),
                np.random.normal(45, 9),
                np.random.normal(850, 110),
                np.random.normal(680, 85),
                np.random.poisson(2),
                np.random.poisson(2),
                0, 0,
                np.random.normal(40, 5),
                np.random.normal(40, 5),
                np.random.normal(1.5, 0.3),
                np.random.normal(1.2, 0.3),
                np.random.normal(70, 15),
                np.random.normal(120, 20),
                np.random.normal(95, 18),
                np.random.normal(22, 6),
                np.random.normal(484, 100),
                np.random.poisson(1),
                np.random.poisson(1),
                0,
                np.random.poisson(4),
                np.random.poisson(50),
                0, 0, 0,
                np.random.normal(0.85, 0.15),
                np.random.normal(100, 18),
                np.random.normal(100, 18),
                np.random.normal(95, 17),
                np.random.normal(40, 5),
                0, 0, 0, 0, 0, 0,
                np.random.poisson(30),
                np.random.normal(3000, 500),
                np.random.poisson(25),
                np.random.normal(2500, 400),
                np.random.choice([8192, 16384]),
                np.random.choice([8192, 16384]),
                np.random.poisson(25),
                np.random.normal(40, 5),
                np.random.normal(15000, 3000),
                np.random.normal(3000, 600),
                np.random.normal(20000, 4000),
                np.random.normal(10000, 2000),
                np.random.normal(5000, 1000),
                np.random.normal(2000, 400),
                np.random.normal(8000, 1600),
                np.random.normal(3000, 600),
            ]
        
        features.append(sample)
    
    print(f"{Fore.GREEN}✅ Generated {n_samples:,} samples\n")
    
    return np.array(features), labels


def save_processed_data(X_train, X_test, y_train, y_test, scaler, 
                       label_encoder, feature_names, class_names):
    """Save all processed data"""
    
    print(f"{Fore.YELLOW}Saving processed data...\n")
    
    out_dir = Path('data/processed')
    out_dir.mkdir(parents=True, exist_ok=True)
    
    # Save arrays
    np.save(out_dir / 'X_train.npy', X_train)
    np.save(out_dir / 'X_test.npy', X_test)
    np.save(out_dir / 'y_train.npy', y_train)
    np.save(out_dir / 'y_test.npy', y_test)
    
    # Save objects
    with open(out_dir / 'scaler.pkl', 'wb') as f:
        pickle.dump(scaler, f)
    
    with open(out_dir / 'label_encoder.pkl', 'wb') as f:
        pickle.dump(label_encoder, f)
    
    with open(out_dir / 'feature_names.json', 'w') as f:
        json.dump(feature_names, f, indent=2)
    
    # Metadata
    metadata = {
        'dataset': 'CIC-IDS2017',
        'n_features': len(feature_names),
        'n_classes': len(class_names),
        'class_names': class_names.tolist(),
        'train_samples': len(X_train),
        'test_samples': len(X_test)
    }
    
    with open(out_dir / 'metadata.json', 'w') as f:
        json.dump(metadata, f, indent=2)
    
    print(f"{Fore.GREEN}✅ Saved to: {out_dir}\n")


def main():
    # Generate data
    X, y_labels = generate_synthetic_ids_data(n_samples=470000)
    
    # Encode labels
    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(y_labels)
    
    # Split
    print(f"{Fore.YELLOW}Splitting data...\n")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Scale
    print(f"{Fore.YELLOW}Scaling features...\n")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Feature names (78 features)
    feature_names = [
        "Destination Port", "Flow Duration", "Total Fwd Packets", 
        "Total Backward Packets", "Total Length of Fwd Packets",
        "Total Length of Bwd Packets", "Fwd Packet Length Max",
        "Fwd Packet Length Min", "Fwd Packet Length Mean",
        "Fwd Packet Length Std", "Bwd Packet Length Max",
        "Bwd Packet Length Min", "Bwd Packet Length Mean",
        "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s",
        "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
        "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max",
        "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std",
        "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags",
        "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length",
        "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
        "Min Packet Length", "Max Packet Length", "Packet Length Mean",
        "Packet Length Std", "Packet Length Variance", "FIN Flag Count",
        "SYN Flag Count", "RST Flag Count", "PSH Flag Count",
        "ACK Flag Count", "URG Flag Count", "CWE Flag Count",
        "ECE Flag Count", "Down/Up Ratio", "Average Packet Size",
        "Avg Fwd Segment Size", "Avg Bwd Segment Size",
        "Fwd Header Length.1", "Fwd Avg Bytes/Bulk",
        "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
        "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk",
        "Bwd Avg Bulk Rate", "Subflow Fwd Packets", "Subflow Fwd Bytes",
        "Subflow Bwd Packets", "Subflow Bwd Bytes",
        "Init_Win_bytes_forward", "Init_Win_bytes_backward",
        "act_data_pkt_fwd", "min_seg_size_forward", "Active Mean",
        "Active Std", "Active Max", "Active Min", "Idle Mean",
        "Idle Std", "Idle Max", "Idle Min"
    ]
    
    # Save
    save_processed_data(
        X_train_scaled, X_test_scaled, y_train, y_test,
        scaler, label_encoder, feature_names, label_encoder.classes_
    )
    
    print(f"{Fore.CYAN}{'='*60}")
    print(f"{Fore.GREEN}✅ DATA GENERATION COMPLETE!")
    print(f"{Fore.CYAN}{'='*60}\n")
    print(f"{Fore.YELLOW}Ready to train!")
    print(f"{Fore.YELLOW}Run: python src/ml/train_fast.py\n")


if __name__ == "__main__":
    main()
