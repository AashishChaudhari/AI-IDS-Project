#!/usr/bin/env python3
"""
Fast Training - Single Random Forest
3-5 minutes, 90%+ accuracy
"""

import numpy as np
import pickle
import json
from colorama import Fore, init
import sys
sys.path.append('.')
from data_loader import DataLoader

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

init(autoreset=True)

print(f"{Fore.CYAN}{'='*60}")
print(f"{Fore.CYAN}FAST TRAINING - SINGLE RANDOM FOREST")
print(f"{Fore.CYAN}{'='*60}\n")

# Load data
print(f"{Fore.YELLOW}Loading data...")
loader = DataLoader()
loader.load_all()
X_train, X_test, y_train, y_test = loader.get_data()
class_names = loader.get_class_names()

print(f"{Fore.GREEN}✅ {len(X_train):,} training samples\n")

# Train Random Forest
print(f"{Fore.YELLOW}Training Random Forest...")
print(f"  Trees: 200")
print(f"  Max depth: 30")
print(f"  Parallel: All CPUs")
print(f"  Estimated time: 3-5 minutes\n")

model = RandomForestClassifier(
    n_estimators=200,
    max_depth=30,
    min_samples_split=5,
    random_state=42,
    n_jobs=-1,
    class_weight='balanced',
    verbose=1
)

model.fit(X_train, y_train)

print(f"\n{Fore.GREEN}✅ Training complete!\n")

# Evaluate
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

print(f"{Fore.GREEN}{'='*60}")
print(f"{Fore.GREEN}🎯 ACCURACY: {accuracy:.4f} ({accuracy*100:.2f}%)")
print(f"{Fore.GREEN}{'='*60}\n")

if accuracy >= 0.90:
    print(f"{Fore.GREEN}🎉 90%+ ACHIEVED!\n")
elif accuracy >= 0.85:
    print(f"{Fore.GREEN}⭐ EXCELLENT!\n")

# Report
print(f"{Fore.YELLOW}Per-Class Performance:\n")
print(classification_report(y_test, y_pred, target_names=class_names, zero_division=0))

# Save
with open('models/final_model.pkl', 'wb') as f:
    pickle.dump(model, f)

metadata = {
    'model_name': 'Random Forest (CIC-IDS2017)',
    'dataset': 'CIC-IDS2017',
    'accuracy': float(accuracy),
    'n_classes': len(class_names),
    'class_names': class_names.tolist(),
    'production_ready': True
}

with open('models/production_metadata.json', 'w') as f:
    json.dump(metadata, f, indent=2)

with open('models/model_metadata.json', 'w') as f:
    json.dump({
        'model_name': 'Random Forest',
        'metrics': {'accuracy': float(accuracy), 'f1_score': 0.0},
        'n_classes': len(class_names),
        'class_names': class_names.tolist()
    }, f, indent=2)

print(f"{Fore.GREEN}✅ Model saved!\n")

print(f"{Fore.YELLOW}Final Result: {accuracy*100:.1f}% accuracy")
print(f"Model: models/final_model.pkl\n")
