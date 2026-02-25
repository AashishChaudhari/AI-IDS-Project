# AI-IDS Model Files

## Required Files
- `rf_model.pkl` - Random Forest classifier (excluded from Git)
- `scaler.pkl` - Feature scaler (excluded from Git)

## Model Performance
- **Accuracy:** 99.81%
- **Dataset:** CIC-IDS2017
- **Features:** 78

## Setup Instructions

### Option 1: Download Pre-trained Models
Download from [Releases](https://github.com/YOUR_USERNAME/AI-IDS-Project/releases)

### Option 2: Train Your Own
1. Download CIC-IDS2017 dataset
2. Place in `data/` directory
3. Run: `python src/training/train_model.py`

## Usage
```python
import joblib
model = joblib.load('models/rf_model.pkl')
scaler = joblib.load('models/scaler.pkl')
```

See main README.md for detailed instructions.
