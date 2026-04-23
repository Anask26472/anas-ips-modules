from __future__ import annotations

import pickle
import sys
from pathlib import Path

import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import joblib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ips.utils.config import DATA_DIR, ENCODERS_MODEL, ISO_MODEL, MODELS_DIR, RF_MODEL

MODELS_DIR.mkdir(parents=True, exist_ok=True)

COLUMNS = [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment",
    "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files",
    "num_outbound_cmds", "is_host_login", "is_guest_login",
    "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label", "difficulty"
]

ATTACK_MAP = {
    "normal": "normal",
    "neptune": "dos", "back": "dos", "land": "dos", "pod": "dos", "smurf": "dos", "teardrop": "dos",
    "mailbomb": "dos", "apache2": "dos", "processtable": "dos", "udpstorm": "dos",
    "ipsweep": "probe", "nmap": "probe", "portsweep": "probe", "satan": "probe", "mscan": "probe", "saint": "probe",
    "ftp_write": "r2l", "guess_passwd": "r2l", "imap": "r2l", "multihop": "r2l", "phf": "r2l", "spy": "r2l", "warezclient": "r2l", "warezmaster": "r2l",
    "buffer_overflow": "u2r", "loadmodule": "u2r", "perl": "u2r", "rootkit": "u2r", "httptunnel": "u2r", "ps": "u2r", "sqlattack": "u2r", "xterm": "u2r",
}


def main() -> None:
    path = DATA_DIR / "KDDTrain+.txt"
    df = pd.read_csv(path, names=COLUMNS)
    df["label"] = df["label"].map(lambda x: ATTACK_MAP.get(str(x).strip(), "other"))
    df = df.drop(columns=["difficulty"])

    encoders = {}
    for col in ["protocol_type", "service", "flag"]:
        enc = LabelEncoder()
        df[col] = enc.fit_transform(df[col].astype(str))
        encoders[col] = enc

    with open(ENCODERS_MODEL, "wb") as fh:
        pickle.dump(encoders, fh)

    X = df.drop(columns=["label"]).values
    y = df["label"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    rf = RandomForestClassifier(n_estimators=100, max_depth=20, random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)
    print(classification_report(y_test, rf.predict(X_test)))

    iso = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    iso.fit(X[y == "normal"])

    joblib.dump(rf, RF_MODEL)
    joblib.dump(iso, ISO_MODEL)
    print("models saved")


if __name__ == "__main__":
    main()
