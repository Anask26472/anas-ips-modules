from __future__ import annotations

import pickle
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.preprocessing import MinMaxScaler
from torch.utils.data import DataLoader, TensorDataset

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ips.core.autoencoder import Autoencoder
from ips.utils.config import AUTO_MODEL, AUTO_SCALER, AUTO_THRESHOLD, DATA_DIR, ENCODERS_MODEL

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


def main() -> None:
    df = pd.read_csv(DATA_DIR / "KDDTrain+.txt", names=COLUMNS)
    with open(ENCODERS_MODEL, "rb") as fh:
        encoders = pickle.load(fh)
    for col, enc in encoders.items():
        df[col] = df[col].apply(lambda x: enc.transform([x])[0] if x in enc.classes_ else 0)

    normal = df[df["label"] == "normal"].drop(columns=["label", "difficulty"]).values.astype(float)
    scaler = MinMaxScaler()
    X = scaler.fit_transform(normal).astype(np.float32)
    with open(AUTO_SCALER, "wb") as fh:
        pickle.dump(scaler, fh)

    dataset = TensorDataset(torch.tensor(X, dtype=torch.float32))
    loader = DataLoader(dataset, batch_size=256, shuffle=True)

    model = Autoencoder()
    opt = torch.optim.Adam(model.parameters(), lr=0.001)
    loss_fn = nn.MSELoss()

    model.train()
    for epoch in range(20):
        total = 0.0
        for (batch,) in loader:
            opt.zero_grad()
            out = model(batch)
            loss = loss_fn(out, batch)
            loss.backward()
            opt.step()
            total += loss.item()
        if (epoch + 1) % 5 == 0:
            print(f"epoch {epoch + 1}/20 loss={total / len(loader):.6f}")

    model.eval()
    with torch.no_grad():
        inp = torch.tensor(X, dtype=torch.float32)
        out = model(inp)
        errors = ((out - inp) ** 2).mean(dim=1).numpy()
        threshold = float(np.percentile(errors, 95))

    torch.save(model.state_dict(), AUTO_MODEL)
    np.save(AUTO_THRESHOLD, threshold)
    print("autoencoder assets saved")


if __name__ == "__main__":
    main()
