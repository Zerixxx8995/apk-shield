"""
Script for Training the Random Forest Classifier on Drebin Feature Vector.
"""
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_val_score
import joblib
import pandas as pd
import numpy as np
import os

FEATURES = [
    # Permissions
    "SEND_SMS",
    "READ_PHONE_STATE",
    "RECEIVE_SMS",
    "READ_SMS",
    "WRITE_SMS",
    "GET_ACCOUNTS",
    "CAMERA",
    "INTERNET",
    "RECORD_AUDIO",
    "NFC",
    "WAKE_LOCK",
    "RECEIVE_BOOT_COMPLETED",
    "RESTART_PACKAGES",
    "BLUETOOTH",
    "READ_CALENDAR",
    "READ_CALL_LOG",
    "READ_EXTERNAL_STORAGE",
    "VIBRATE",
    "ACCESS_NETWORK_STATE",
    "ACCESS_WIFI_STATE",
    "WRITE_EXTERNAL_STORAGE",
    "ACCESS_FINE_LOCATION",
    "ACCESS_COARSE_LOCATION",
    "SYSTEM_ALERT_WINDOW",
    "DISABLE_KEYGUARD",
    # APIs & Callbacks
    "transact",
    "onServiceConnected",
    "bindService",
    "ClassLoader",
    "DexClassLoader",
    "PathClassLoader",
    "Runtime.getRuntime",
    "Runtime.exec",
    "System.loadLibrary",
    "Ljavax.crypto.Cipher",
    "TelephonyManager.getDeviceId",
    "TelephonyManager.getSubscriberId",
    "TelephonyManager.getLine1Number",
    "TelephonyManager.getSimSerialNumber",
    "android.intent.action.BOOT_COMPLETED"
]

def train_and_save():
    csv_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'drebin-215-dataset-5560malware-9476-benign.csv')
    if not os.path.exists(csv_path):
        print(f"Dataset not found at {csv_path}")
        return

    print("Loading Drebin dataset...")
    df = pd.read_csv(csv_path, low_memory=False)
    
    # Process features
    X = df[FEATURES].copy()
    for col in FEATURES:
        X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0).astype(int)
    
    X = X.values
    y = df['class'].apply(lambda x: 1 if x == 'S' else 0).values

    print(f"Dataset loaded. Features shape: {X.shape}, Labels shape: {y.shape}")
    print(f"Malware samples: {np.sum(y)}, Benign samples: {len(y) - np.sum(y)}")
    
    print("Training Random Forest Classifier...")
    clf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
    
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    print("Evaluating model with 5-fold cross validation...")
    scores = cross_val_score(clf, X, y, cv=cv, scoring='accuracy')
    print(f"Cross-validated accuracy: {scores.mean():.4f} (+/- {scores.std():.4f})")
    
    # Train final model on all data
    clf.fit(X, y)
    
    model_path = os.path.join(os.path.dirname(__file__), 'model.pkl')
    joblib.dump(clf, model_path)
    print(f"Model saved to {model_path}")

if __name__ == "__main__":
    train_and_save()
