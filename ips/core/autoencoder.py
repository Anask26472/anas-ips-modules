from __future__ import annotations

import pickle

import numpy as np

from ips.utils.config import AUTO_MODEL, AUTO_SCALER, AUTO_THRESHOLD
from ips.utils.logger import get_logger

log = get_logger(__name__)

TORCH_AVAILABLE = False
TORCH_IMPORT_ERROR = None

try:
    import torch
    import torch.nn as nn
    TORCH_AVAILABLE = True
except Exception as exc:
    torch = None
    nn = None
    TORCH_IMPORT_ERROR = exc
    log.warning(f"torch is not available, autoencoder disabled: {exc}")


if TORCH_AVAILABLE:
    class Autoencoder(nn.Module):
        def __init__(self):
            super().__init__()
            self.encoder = nn.Sequential(
                nn.Linear(41, 32),
                nn.ReLU(),
                nn.Linear(32, 16),
                nn.ReLU(),
                nn.Linear(16, 8),
                nn.ReLU(),
            )
            self.decoder = nn.Sequential(
                nn.Linear(8, 16),
                nn.ReLU(),
                nn.Linear(16, 32),
                nn.ReLU(),
                nn.Linear(32, 41),
                nn.Sigmoid(),
            )

        def forward(self, x):
            return self.decoder(self.encoder(x))
else:
    class Autoencoder:
        pass


class ZeroDayDetector:
    def __init__(self):
        self.model: Autoencoder | None = None
        self.scaler = None
        self.threshold = None
        self.ready = False
        self._load()

    def _load(self) -> None:
        if not TORCH_AVAILABLE:
            log.warning("autoencoder disabled because torch could not be imported")
            self.ready = False
            return

        try:
            if not AUTO_MODEL.exists() or not AUTO_THRESHOLD.exists() or not AUTO_SCALER.exists():
                log.warning("autoencoder assets not found; zero-day-like check disabled")
                return

            self.model = Autoencoder()
            self.model.load_state_dict(torch.load(AUTO_MODEL, map_location="cpu"))
            self.model.eval()
            self.threshold = float(np.load(AUTO_THRESHOLD))

            with open(AUTO_SCALER, "rb") as fh:
                self.scaler = pickle.load(fh)

            self.ready = True
            log.info(f"autoencoder ready with threshold {self.threshold:.6f}")
        except Exception as exc:
            log.error(f"failed to load autoencoder assets: {exc}")
            self.ready = False

    def analyze(self, vector: np.ndarray) -> dict:
        if not self.ready or self.model is None or self.scaler is None or not TORCH_AVAILABLE:
            return {
                "triggered": False,
                "score": 0.0,
                "reasons": [],
                "enabled": False,
            }

        scaled = self.scaler.transform([vector])[0].astype(np.float32)

        with torch.no_grad():
            x = torch.tensor(scaled, dtype=torch.float32).unsqueeze(0)
            out = self.model(x)
            errors = ((out - x) ** 2).squeeze().numpy()
            mse = float(np.mean(errors))

        top_idx = np.argsort(errors)[::-1][:3]
        feature_names = [
            "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
            "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
            "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
            "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login",
            "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
            "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
            "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
            "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
            "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
        ]

        reasons = [
            {"feature": feature_names[i], "error": round(float(errors[i]), 4)}
            for i in top_idx
        ]

        return {
            "triggered": mse > float(self.threshold),
            "score": round(mse, 4),
            "reasons": reasons,
            "enabled": True,
        }