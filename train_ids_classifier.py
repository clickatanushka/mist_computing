"""
=============================================================
  IDS Multi-Attack Classifier Trainer
  Dataset : CIC-IDS2017  (MachineLearningCSV.zip)
  Download: https://www.unb.ca/cic/datasets/ids-2017.html
  
  Trains ONE Random Forest classifier that outputs:
      0 = BENIGN
      1 = DDOS
      2 = MITM   (mapped from ARP-Spoofing / Infiltration)
      3 = SQLI   (mapped from Web-Attack-SQL-Injection)

  Then derives per-layer, per-attack threshold profiles
  (rate, jitter, latency, payload_size, entropy) from
  feature statistics in the training data and writes them
  to  →  ids_profiles.json   (consumed by OMNeT++ controller)
  and →  ids_model.pkl       (used by the live Python monitor)
=============================================================
"""

import os, json, warnings
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib

warnings.filterwarnings("ignore")

# ── 0. CONFIG ────────────────────────────────────────────────
CSV_DIR   = Path("./CIC-IDS2017-CSV/MachineLearningCVE")  
# Only load files containing our 3 attack types — saves RAM
LOAD_ONLY = [
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",       # DDoS
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",  # MitM
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",  # SQLi
]# folder with the downloaded CSVs
OUT_MODEL  = Path("ids_model.pkl")
OUT_PROFILES = Path("ids_profiles.json")

# CIC-IDS2017 label → our 4-class scheme
LABEL_MAP = {
    "BENIGN"                        : "BENIGN",
    "DDoS"                          : "DDOS",
    "DoS Hulk"                      : "DDOS",
    "DoS GoldenEye"                 : "DDOS",
    "DoS slowloris"                 : "DDOS",
    "DoS Slowhttptest"              : "DDOS",
    "Heartbleed"                    : "DDOS",
    "Infiltration"                  : "MITM",
    "Bot"                           : "MITM",       # C2 channel similar to MitM
    "Web Attack – Sql Injection"    : "SQLI",
    "Web Attack \x96 Sql Injection" : "SQLI",       # encoding variant
    "Web Attack - Sql Injection"    : "SQLI",
    "Web Attack  Sql Injection"     : "SQLI",
}

# Features that map to things EdgeNode / OMNeT++ can observe
FEATURES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",        # inter-arrival time → jitter proxy
    "Flow IAT Std",
    "Fwd IAT Mean",
    "Bwd IAT Mean",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "Average Packet Size",
    "Avg Fwd Segment Size",
]

# ── 1. LOAD & LABEL ─────────────────────────────────────────
def load_data(csv_dir: Path) -> pd.DataFrame:
    files = [csv_dir / f for f in LOAD_ONLY if (csv_dir / f).exists()]
    if not files:
        raise FileNotFoundError(
            f"No CSV files found in {csv_dir}.\n"
            "Download CIC-IDS2017 from:\n"
            "  https://www.unb.ca/cic/datasets/ids-2017.html\n"
            "Extract MachineLearningCSV.zip and set CSV_DIR above."
        )
    print(f"Loading {len(files)} CSV files …")
    dfs = []
    for f in files:
        try:
            df = pd.read_csv(f, encoding="utf-8", low_memory=False, nrows=50000)
            df.columns = df.columns.str.strip()
            dfs.append(df)
            print(f"  {f.name}: {len(df):,} rows")
        except Exception as e:
            print(f"  SKIP {f.name}: {e}")
    return pd.concat(dfs, ignore_index=True)

def clean_and_map(df: pd.DataFrame) -> pd.DataFrame:
    label_col = [c for c in df.columns if "label" in c.lower()][0]
    df["attack_class"] = df[label_col].str.strip().map(LABEL_MAP)

    # drop unknowns and keep only our 4 classes
    df = df[df["attack_class"].notna()].copy()

    # keep only needed features + label
    available = [f for f in FEATURES if f in df.columns]
    df = df[available + ["attack_class"]].copy()

    # replace inf / nan
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    print(f"\nClass distribution after mapping:")
    print(df["attack_class"].value_counts())
    return df, available

# ── 2. TRAIN ────────────────────────────────────────────────
def train(df: pd.DataFrame, feature_cols: list):
    le = LabelEncoder()
    y  = le.fit_transform(df["attack_class"])
    X  = df[feature_cols].values

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("\nTraining Random Forest …")
    clf = RandomForestClassifier(
        n_estimators=150,
        max_depth=18,
        min_samples_leaf=5,
        n_jobs=-1,
        random_state=42,
        class_weight="balanced",   # handles imbalanced classes
    )
    clf.fit(X_tr, y_tr)

    y_pred = clf.predict(X_te)
    print("\n── Classification Report ──")
    print(classification_report(y_te, y_pred, target_names=le.classes_))

    return clf, le, feature_cols

# ── 3. DERIVE THRESHOLD PROFILES ────────────────────────────
"""
For each attack class we compute the 95th-percentile of each
metric from the ATTACK traffic itself.  These become the
thresholds that each layer uses.

Layer thresholds are SCALED DOWN from cloud → edge:
  Edge   → tightest (frontline, catches mass floods)
  MIST   → moderate
  Fog    → moderate-strict
  Cloud  → wide net (catches stragglers)

The scaling factor per layer:
  edge ×0.5 | mist ×0.7 | fog ×0.85 | cloud ×1.0
"""

LAYER_SCALE = {
    "edge"  : 0.50,
    "mist"  : 0.70,
    "fog"   : 0.85,
    "cloud" : 1.00,
}

# Which dataset column maps to which OMNeT++ metric
METRIC_COL_MAP = {
    "rate_pps"      : "Flow Packets/s",
    "jitter_s"      : "Flow IAT Std",    # std of inter-arrival → jitter
    "latency_s"     : "Flow IAT Mean",   # mean inter-arrival → latency proxy
    "payload_bytes" : "Average Packet Size",
    "entropy"       : "Packet Length Std",  # variance of lengths → entropy proxy
}

def derive_profiles(df: pd.DataFrame) -> dict:
    profiles = {}
    for cls in ["DDOS", "MITM", "SQLI"]:
        sub = df[df["attack_class"] == cls]
        if len(sub) == 0:
            print(f"  WARNING: no samples for {cls}")
            continue

        base = {}
        for metric, col in METRIC_COL_MAP.items():
            if col in sub.columns:
                val = float(np.percentile(sub[col].dropna(), 95))
                # convert pps from per-second to sensible OMNeT++ int
                if metric == "rate_pps":
                    val = max(2, int(val))
                elif metric in ("jitter_s", "latency_s"):
                    val = round(val / 1_000_000, 4)   # microseconds → seconds
                else:
                    val = round(val, 4)
                base[metric] = val

        profiles[cls] = {}
        for layer, scale in LAYER_SCALE.items():
            profiles[cls][layer] = {}
            for metric, val in base.items():
                if metric == "rate_pps":
                    profiles[cls][layer][metric] = max(2, int(val * scale))
                else:
                    profiles[cls][layer][metric] = round(val * scale, 6)

        # ── extra per-attack rules ──────────────────────────
        # DDoS   → rate is primary, tight thresholds
        # MitM   → latency + jitter primary, payload secondary
        # SQLi   → payload size + entropy primary, rate loose
        if cls == "DDOS":
            for layer in profiles[cls]:
                profiles[cls][layer]["primary_rule"] = "rate"
                profiles[cls][layer]["secondary_rule"] = "jitter"
        elif cls == "MITM":
            for layer in profiles[cls]:
                profiles[cls][layer]["primary_rule"] = "latency"
                profiles[cls][layer]["secondary_rule"] = "jitter"
        elif cls == "SQLI":
            for layer in profiles[cls]:
                profiles[cls][layer]["primary_rule"] = "payload"
                profiles[cls][layer]["secondary_rule"] = "entropy"

    return profiles

# ── 4. FALLBACK PROFILES (when dataset not available) ────────
"""
If you haven't downloaded the dataset yet these hardcoded
profiles let you test the OMNeT++ code immediately.
Values are based on published CIC-IDS2017 statistics.
"""
FALLBACK_PROFILES = {
    "DDOS": {
        "edge"  : {"rate_pps":5,  "jitter_s":0.010, "latency_s":0.050, "payload_bytes":80,   "entropy":30,  "primary_rule":"rate",    "secondary_rule":"jitter"},
        "mist"  : {"rate_pps":7,  "jitter_s":0.025, "latency_s":0.100, "payload_bytes":100,  "entropy":40,  "primary_rule":"rate",    "secondary_rule":"jitter"},
        "fog"   : {"rate_pps":9,  "jitter_s":0.050, "latency_s":0.200, "payload_bytes":120,  "entropy":50,  "primary_rule":"rate",    "secondary_rule":"jitter"},
        "cloud" : {"rate_pps":12, "jitter_s":0.100, "latency_s":0.400, "payload_bytes":150,  "entropy":60,  "primary_rule":"rate",    "secondary_rule":"jitter"},
    },
    "MITM": {
        "edge"  : {"rate_pps":10, "jitter_s":0.005, "latency_s":0.020, "payload_bytes":200,  "entropy":80,  "primary_rule":"latency", "secondary_rule":"jitter"},
        "mist"  : {"rate_pps":14, "jitter_s":0.015, "latency_s":0.055, "payload_bytes":250,  "entropy":100, "primary_rule":"latency", "secondary_rule":"jitter"},
        "fog"   : {"rate_pps":17, "jitter_s":0.035, "latency_s":0.120, "payload_bytes":300,  "entropy":120, "primary_rule":"latency", "secondary_rule":"jitter"},
        "cloud" : {"rate_pps":20, "jitter_s":0.070, "latency_s":0.250, "payload_bytes":400,  "entropy":150, "primary_rule":"latency", "secondary_rule":"jitter"},
    },
    "SQLI": {
        "edge"  : {"rate_pps":15, "jitter_s":0.020, "latency_s":0.080, "payload_bytes":300,  "entropy":120, "primary_rule":"payload", "secondary_rule":"entropy"},
        "mist"  : {"rate_pps":20, "jitter_s":0.040, "latency_s":0.150, "payload_bytes":500,  "entropy":180, "primary_rule":"payload", "secondary_rule":"entropy"},
        "fog"   : {"rate_pps":25, "jitter_s":0.075, "latency_s":0.280, "payload_bytes":700,  "entropy":220, "primary_rule":"payload", "secondary_rule":"entropy"},
        "cloud" : {"rate_pps":30, "jitter_s":0.120, "latency_s":0.450, "payload_bytes":1000, "entropy":280, "primary_rule":"payload", "secondary_rule":"entropy"},
    },
}

# ── 5. MAIN ──────────────────────────────────────────────────
if __name__ == "__main__":
    if CSV_DIR.exists() and any(CSV_DIR.glob("*.csv")):
        df_raw = load_data(CSV_DIR)
        df, feat_cols = clean_and_map(df_raw)
        clf, le, feat_cols = train(df, feat_cols)

        # save model
        joblib.dump({"model": clf, "label_encoder": le,
                     "features": feat_cols}, OUT_MODEL)
        print(f"\nModel saved → {OUT_MODEL}")

        profiles = derive_profiles(df)
    else:
        print(f"[INFO] Dataset folder '{CSV_DIR}' not found.")
        print("       Using FALLBACK hardcoded profiles derived from")
        print("       published CIC-IDS2017 statistics.")
        print("       Download dataset and re-run to get trained thresholds.\n")
        profiles = FALLBACK_PROFILES

    with open(OUT_PROFILES, "w") as f:
        json.dump(profiles, f, indent=2)
    print(f"Profiles saved → {OUT_PROFILES}")
    print(json.dumps(profiles, indent=2))
