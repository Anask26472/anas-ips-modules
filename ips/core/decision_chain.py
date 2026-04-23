from __future__ import annotations

from ips.utils.config import ANOMALY_BLOCK_COUNT, ANOMALY_PACKET_RATE_THRESHOLD, BLOCK_SCORE, THROTTLE_SCORE

KNOWN_ATTACKS = {'dos', 'probe', 'r2l', 'u2r'}


def decide_action(features: dict, ml_result: dict, autoencoder_ready: bool) -> dict:
    label = ml_result.get('label', 'unknown')
    score = float(ml_result.get('score', 0.0))
    packet_rate = float(features.get('src_packet_rate', 0.0))
    count = int(features.get('count', 0))

    if label in KNOWN_ATTACKS:
        return {
            'label': label,
            'score': score,
            'layer': 'L1-RandomForest',
            'action': _score_action(score),
        }

    if label == 'anomaly':
        action = 'monitor'
        if count >= ANOMALY_BLOCK_COUNT or packet_rate >= ANOMALY_PACKET_RATE_THRESHOLD:
            action = 'block'
        elif score >= THROTTLE_SCORE:
            action = 'throttle'
        return {
            'label': 'anomaly',
            'score': score,
            'layer': 'L2-IsolationForest',
            'action': action,
        }

    if label == 'zero_day_like' and autoencoder_ready:
        action = 'monitor'
        if score >= 0.08 or packet_rate >= ANOMALY_PACKET_RATE_THRESHOLD:
            action = 'block'
        elif score >= 0.05:
            action = 'throttle'
        return {
            'label': 'zero_day_like',
            'score': score,
            'layer': 'L3-Autoencoder',
            'action': action,
        }

    return {
        'label': 'normal',
        'score': score,
        'layer': 'passed',
        'action': 'allow',
    }


def _score_action(score: float) -> str:
    if score >= BLOCK_SCORE:
        return 'block'
    if score >= THROTTLE_SCORE:
        return 'throttle'
    return 'monitor'
