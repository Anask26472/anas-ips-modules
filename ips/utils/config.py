from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
MODELS_DIR = BASE_DIR / 'models'
LOGS_DIR = BASE_DIR / 'logs'
QUARANTINE_DIR = BASE_DIR / 'quarantine'
DATA_DIR = BASE_DIR / 'data'
DOCS_DIR = BASE_DIR / 'docs'
CONFIGS_DIR = BASE_DIR / 'configs'
DEPLOY_DIR = BASE_DIR / 'deploy'

RF_MODEL = MODELS_DIR / 'rf_classifier.pkl'
ISO_MODEL = MODELS_DIR / 'isolation_forest.pkl'
ENCODERS_MODEL = MODELS_DIR / 'encoders.pkl'
AUTO_MODEL = MODELS_DIR / 'autoencoder.pt'
AUTO_THRESHOLD = MODELS_DIR / 'ae_threshold.npy'
AUTO_SCALER = MODELS_DIR / 'ae_scaler.pkl'
BASELINE_FILE = MODELS_DIR / 'baseline_summary.json'
QUARANTINE_FILE = QUARANTINE_DIR / 'unknown_threats.json'
LOG_FILE = LOGS_DIR / 'threats.log'
PERFORMANCE_FILE = LOGS_DIR / 'performance.json'
EVENT_LOG_FILE = LOGS_DIR / 'events.jsonl'
AUDIT_LOG_FILE = LOGS_DIR / 'audit.jsonl'
BLOCK_STATE_FILE = LOGS_DIR / 'block_state.json'
API_TOKENS_FILE = CONFIGS_DIR / 'api_tokens.json'
POLICY_PROFILES_FILE = CONFIGS_DIR / 'policy_profiles.json'
INTEL_INDICATORS_FILE = CONFIGS_DIR / 'intel_indicators.json'

DEFAULT_INTERFACE = os.environ.get('IPS_INTERFACE') or None
API_HOST = os.environ.get('IPS_API_HOST', '127.0.0.1')
API_PORT = int(os.environ.get('IPS_API_PORT', '5050'))
API_TOKEN = os.environ.get('IPS_API_TOKEN', 'change-me')
ENABLE_BRIDGE = os.environ.get('IPS_ENABLE_BRIDGE', '0') == '1'

# Decision policy
ANOMALY_MONITOR_SCORE = float(os.environ.get('IPS_ANOMALY_MONITOR_SCORE', '0.55'))
THROTTLE_SCORE = float(os.environ.get('IPS_THROTTLE_SCORE', '0.70'))
BLOCK_SCORE = float(os.environ.get('IPS_BLOCK_SCORE', '0.85'))
ANOMALY_BLOCK_COUNT = int(os.environ.get('IPS_ANOMALY_BLOCK_COUNT', '25'))
BASELINE_LEARNING_SECONDS = int(os.environ.get('IPS_BASELINE_SECONDS', '60'))

# Flow tracking and rule detection
FLOW_WINDOW_SECONDS = float(os.environ.get('IPS_FLOW_WINDOW_SECONDS', '5'))
SOURCE_WINDOW_SECONDS = float(os.environ.get('IPS_SOURCE_WINDOW_SECONDS', '5'))
PORT_SCAN_PORT_THRESHOLD = int(os.environ.get('IPS_PORT_SCAN_PORT_THRESHOLD', '12'))
PORT_SCAN_PACKET_THRESHOLD = int(os.environ.get('IPS_PORT_SCAN_PACKET_THRESHOLD', '20'))
FLOOD_PACKET_RATE = int(os.environ.get('IPS_FLOOD_PACKET_RATE', '80'))
FLOOD_BYTE_RATE = int(os.environ.get('IPS_FLOOD_BYTE_RATE', '250000'))
SYN_BURST_THRESHOLD = int(os.environ.get('IPS_SYN_BURST_THRESHOLD', '20'))
ICMP_BURST_THRESHOLD = int(os.environ.get('IPS_ICMP_BURST_THRESHOLD', '40'))
ANOMALY_PACKET_RATE_THRESHOLD = int(os.environ.get('IPS_ANOMALY_PACKET_RATE_THRESHOLD', '25'))

# Response policy
AUTO_BLOCK = os.environ.get('IPS_AUTO_BLOCK', '1') == '1'
ENABLE_BLOCKING = os.environ.get('IPS_ENABLE_BLOCKING', '1') == '1'
DEFAULT_BLOCK_TTL_SECONDS = int(os.environ.get('IPS_BLOCK_TTL_SECONDS', '900'))
MAX_BLOCKED_IPS = int(os.environ.get('IPS_MAX_BLOCKED_IPS', '250'))
WHITELISTED_IPS = {
    ip.strip() for ip in os.environ.get('IPS_WHITELIST', '127.0.0.1,::1').split(',') if ip.strip()
}

# Enterprise-style integrations
SURICATA_EVE_FILE = os.environ.get('IPS_SURICATA_EVE_FILE', '')
ENABLE_EVE_EXPORT = os.environ.get('IPS_ENABLE_EVE_EXPORT', '1') == '1'
SIEM_PROFILE = os.environ.get('IPS_SIEM_PROFILE', 'eve-json')

for folder in (MODELS_DIR, LOGS_DIR, QUARANTINE_DIR, DATA_DIR, DOCS_DIR, CONFIGS_DIR, DEPLOY_DIR):
    folder.mkdir(parents=True, exist_ok=True)


USERS_FILE = CONFIGS_DIR / 'users.json'
UPDATE_KEYS_FILE = CONFIGS_DIR / 'update_public_keys.json'
HA_CONFIG_FILE = CONFIGS_DIR / 'ha.json'
SESSION_SECRET = os.environ.get('IPS_SESSION_SECRET', 'dev-session-secret-change-me')
SESSION_COOKIE_NAME = os.environ.get('IPS_SESSION_COOKIE_NAME', 'ips_session')
SESSION_COOKIE_SECURE = os.environ.get('IPS_SESSION_COOKIE_SECURE', '0') == '1'
BOOTSTRAP_ADMIN_USER = os.environ.get('IPS_BOOTSTRAP_ADMIN_USER', 'admin')
BOOTSTRAP_ADMIN_PASSWORD = os.environ.get('IPS_BOOTSTRAP_ADMIN_PASSWORD', 'change-me-now')
DEFAULT_FAIL_MODE = os.environ.get('IPS_FAIL_MODE', 'fail-open')
UPDATE_CHANNEL = os.environ.get('IPS_UPDATE_CHANNEL', 'stable')
