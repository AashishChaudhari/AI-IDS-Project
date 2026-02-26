# AI-IDS Model Files

## Overview

This directory contains the trained machine learning models for the AI-IDS system. The model files are **excluded from Git** due to their large size (11MB+).

## Required Files

- `rf_model.pkl` - Random Forest classifier (11.5 MB)
- `scaler.pkl` - StandardScaler for feature normalization (~1 KB)

## Model Specifications

### Training Details
- **Algorithm:** Random Forest Classifier
- **Dataset:** CIC-IDS2017
- **Training Samples:** 376,437
- **Test Samples:** 94,110
- **Features:** 78 network flow features

### Performance Metrics
- **Accuracy:** 99.81%
- **Precision:** 99.82% (weighted avg)
- **Recall:** 99.81% (weighted avg)
- **F1-Score:** 99.81%
- **False Positive Rate:** 0.19%

### Per-Class Performance
| Class | Precision | Recall | F1-Score | Support |
|-------|-----------|--------|----------|---------|
| BENIGN | 1.00 | 1.00 | 1.00 | 73,832 |
| DDoS | 1.00 | 1.00 | 1.00 | 10,315 |
| PortScan | 1.00 | 1.00 | 1.00 | 9,584 |
| Bot | 0.49 | 0.96 | 0.65 | 379 |

## How to Get the Models

### Option 1: Download Pre-trained Models
Download from the [Releases](https://github.com/YOUR_USERNAME/AI-IDS-Project/releases) page:
1. Go to Releases
2. Download `rf_model.pkl` and `scaler.pkl`
3. Place them in this `models/` directory

### Option 2: Train Your Own Model

1. **Download the CIC-IDS2017 Dataset:**
```bash
   # Visit: https://www.unb.ca/cic/datasets/ids-2017.html
   # Download the CSV files (e.g., Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv)
   # Place in data/ directory
```

2. **Install training dependencies:**
```bash
   pip install pandas scikit-learn joblib numpy
```

3. **Train the model:**
```bash
   python src/training/train_model.py
```

4. **Verify model files:**
```bash
   ls -lh models/
   # Should show rf_model.pkl and scaler.pkl
```

## Feature List (78 features)

The model expects the following 78 features extracted from network flows:

### Packet Statistics (14)
- fwd_pkts, bwd_pkts
- fwd_pkt_len_tot, bwd_pkt_len_tot
- fwd_pkt_len_max, fwd_pkt_len_min, fwd_pkt_len_mean, fwd_pkt_len_std
- bwd_pkt_len_max, bwd_pkt_len_min, bwd_pkt_len_mean, bwd_pkt_len_std
- pkt_len, pkt_len_max, pkt_len_min, pkt_len_mean, pkt_len_std, pkt_len_var

### Flow Features (11)
- flow_duration
- flow_pkts_per_sec, flow_bytes_per_sec
- fwd_pkts_per_sec, bwd_pkts_per_sec
- flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min
- down_up_ratio, avg_pkt_size

### TCP Flags (10)
- fwd_urg_flags, fwd_psh_flags, fwd_rst_flags, fwd_syn_flags, fwd_fin_flags
- bwd_urg_flags, bwd_psh_flags, bwd_rst_flags, bwd_syn_flags, bwd_fin_flags

### Inter-Arrival Time (8)
- fwd_iat_tot, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min
- bwd_iat_tot, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min

### Header & Payload (6)
- fwd_hdr_len, bwd_hdr_len
- fwd_seg_size_avg, bwd_seg_size_avg, fwd_seg_size_min
- fwd_act_data_pkts

### Bulk Transfer (6)
- fwd_bulk_rate, fwd_bulk_pkts, fwd_bulk_bytes
- bwd_bulk_rate, bwd_bulk_pkts, bwd_bulk_bytes

### Subflow (4)
- subflow_fwd_pkts, subflow_fwd_bytes
- subflow_bwd_pkts, subflow_bwd_bytes

### Active/Idle (8)
- active_mean, active_std, active_max, active_min
- idle_mean, idle_std, idle_max, idle_min

### Window & Protocol (4)
- init_fwd_win_bytes, init_bwd_win_bytes
- protocol, src_port, dst_port

## Model Architecture
```python
RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1,
    class_weight='balanced'
)
```

## Usage in Code
```python
import joblib
import numpy as np

# Load model and scaler
model = joblib.load('models/rf_model.pkl')
scaler = joblib.load('models/scaler.pkl')

# Prepare features (78 features)
features = np.array([...])  # Your 78 features
features_scaled = scaler.transform(features)

# Predict
prediction = model.predict(features_scaled)
confidence = model.predict_proba(features_scaled).max()

print(f"Prediction: {prediction[0]}")
print(f"Confidence: {confidence * 100:.2f}%")
```

## Retraining the Model

To retrain with new data:
```python
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import joblib

# Your training code here
model = RandomForestClassifier(n_estimators=100, random_state=42)
scaler = StandardScaler()

# Train
X_scaled = scaler.fit_transform(X_train)
model.fit(X_scaled, y_train)

# Save
joblib.dump(model, 'models/rf_model.pkl')
joblib.dump(scaler, 'models/scaler.pkl')
```

## Troubleshooting

**Error: "Model expects 78 features but got 14"**
- Solution: Ensure you're extracting all 78 features from packets
- Check `src/capture/packet_capture.py` feature extraction function

**Model file not found:**
- Solution: Train the model or download pre-trained version
- Verify files exist: `ls -lh models/*.pkl`

## Contact

For model-related questions:
- Open an issue on GitHub
- Email: your-email@example.com
