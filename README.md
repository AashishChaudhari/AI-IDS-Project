# AI-Powered Intrusion Detection System (IDS)

Real-time network intrusion detection using machine learning. Classifies live network traffic into benign or attack categories with **99.81% accuracy**.

---

## Architecture
```
Attacker VM ──► Network ──► Packet Capture ──► Feature Extraction ──► ML Model ──► Dashboard
                              (Scapy)           (78 CIC-IDS2017       (Random       (Flask)
                                                 features)             Forest)
```

---

## Detection Results

| Attack Type | Precision | Recall | F1-Score |
|-------------|-----------|--------|----------|
| BENIGN      | 1.00      | 1.00   | 1.00     |
| DDoS        | 1.00      | 1.00   | 1.00     |
| PortScan    | 1.00      | 1.00   | 1.00     |
| Bot         | 0.49      | 0.96   | 0.65     |

**Overall Accuracy: 99.81%** on 94,110 test samples.

---

## Project Structure
```
AI-IDS-Project/
├── src/
│   ├── capture/
│   │   └── packet_capture.py          # Live packet capture, flow reconstruction, prediction
│   ├── dashboard/
│   │   └── app_live.py                # Flask dashboard with real-time alerts
│   ├── preprocessing/
│   │   └── cicids2017_preprocessor.py # CIC-IDS2017 dataset preprocessing pipeline
│   └── ml/
│       └── train_fast.py              # Random Forest model training
├── models/
│   ├── final_model.pkl                # Trained model (gitignored)
│   ├── model_metadata.json
│   └── production_metadata.json
├── data/
│   ├── raw/                           # CIC-IDS2017 CSVs (download separately)
│   └── processed/                     # Preprocessed data (gitignored)
├── docs/visualizations/               # Training charts
├── reports/                           # Generated PDF reports
├── requirements.txt
├── .gitignore
└── README.md
```

---

## Setup
```bash
git clone https://github.com/AashishChaudhari/AI-IDS-Project.git
cd AI-IDS-Project
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Train the Model
```bash
# 1. Download CIC-IDS2017: https://www.kaggle.com/datasets/cicdataset/cicids2017
#    Extract CSVs into: data/raw/cicids2017/

# 2. Preprocess
python src/preprocessing/cicids2017_preprocessor.py --samples 500000

# 3. Train (~2.4 minutes)
python src/ml/train_fast.py
```

---

## Run the IDS

**Terminal 1 — Packet Capture** (needs root):
```bash
sudo ~/AI-IDS-Project/venv/bin/python src/capture/packet_capture.py --iface eth0
```

**Terminal 2 — Dashboard:**
```bash
source venv/bin/activate
python src/dashboard/app_live.py
```

Open **http://127.0.0.1:5000**

---

## Test with Attacks
```bash
nmap -sV 192.168.x.x                       # Port Scan
sudo hping3 -S --flood 192.168.x.x         # SYN Flood
sudo hping3 --udp --flood 192.168.x.x      # UDP Flood
sudo hping3 --icmp --flood 192.168.x.x     # ICMP Flood
```

---

## How It Works

1. **Capture** — Scapy sniffs all IP packets on the interface
2. **Flow Reconstruction** — Packets grouped by 5-tuple, completed on FIN/RST or 2s timeout
3. **Feature Extraction** — 78 features per flow matching CIC-IDS2017 schema
4. **Classification** — StandardScaler + Random Forest predicts class and confidence
5. **Dashboard** — Predictions written to shared JSON, dashboard polls every 2 seconds

---

## Dataset

CIC-IDS2017 from the Canadian Institute for Cybersecurity.
- Samples: 470,547 | Features: 78
- Classes: BENIGN (78.6%), DDoS (11.0%), PortScan (10.2%), Bot (0.2%)
- Download: https://www.kaggle.com/datasets/cicdataset/cicids2017
