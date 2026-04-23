from __future__ import annotations

import pickle
from typing import Any

import joblib
import numpy as np

from ips.core.autoencoder import ZeroDayDetector
from ips.core.feature_builder import build_model_vector
from ips.utils.config import ENCODERS_MODEL, ISO_MODEL, RF_MODEL
from ips.utils.logger import get_logger

log = get_logger(__name__)


class MLModelEngine:
    def __init__(self):
        self.rf_model = None
        self.iso_model = None
        self.encoders: dict[str, Any] = {}
        self.autoencoder = ZeroDayDetector()
        self._load()

    @property
    def autoencoder_ready(self) -> bool:
        return self.autoencoder.ready

    def _load(self) -> None:
        try:
            self.rf_model = joblib.load(RF_MODEL)
            self.iso_model = joblib.load(ISO_MODEL)
            with open(ENCODERS_MODEL, "rb") as fh:
                self.encoders = pickle.load(fh)
            log.info("RF, Isolation Forest, and encoders loaded")
        except Exception as exc:
            log.error(f"failed to load ML assets: {exc}")

    def analyze(self, features: dict[str, Any]) -> dict[str, Any]:
        if self.rf_model is None or self.iso_model is None:
            return {
                "label": "unknown",
                "score": 0.0,
                "confidence": 0.0,
                "vector": None,
                "ae": None,
            }

        vector = build_model_vector(features, self.encoders)
        rf_label = str(self.rf_model.predict(vector)[0])
        rf_score = float(np.max(self.rf_model.predict_proba(vector)))
        iso_label = int(self.iso_model.predict(vector)[0])

        ae_result = self.autoencoder.analyze(vector[0])

        label = "normal"
        score = rf_score
        confidence = round(rf_score * 100, 1)

        if rf_label != "normal":
            label = rf_label
        elif iso_label == -1:
            label = "anomaly"
            score = max(score, 0.75)
            confidence = 75.0
        elif ae_result["triggered"]:
            label = "zero_day_like"
            score = ae_result["score"]
            confidence = round(min(ae_result["score"], 1.0) * 100, 1)

        return {
            "label": label,
            "score": round(float(score), 4),
            "confidence": confidence,
            "vector": vector,
            "ae": ae_result,
        }
