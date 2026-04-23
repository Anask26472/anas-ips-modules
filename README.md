# Anas IPS Modules v1.1

Developed by **Anas**

This project is a **host-based Intrusion Prevention System (IPS) module** developed as a university information security project.  
It monitors live network traffic, detects suspicious behavior using **machine learning and deep learning**, and applies host-side response actions such as **blocking** and **throttling**.

---

## What this project does

This version currently supports:

- live packet capture using **Scapy**
- packet and short-window flow feature generation
- rule-based detection for obvious scan/flood patterns
- **Random Forest** for known attack classification
- **Isolation Forest** for anomaly detection
- **Autoencoder** for zero-day-like anomaly detection
- event logging and quarantine storage
- **Windows Firewall** based blocking
- **Windows QoS** based throttling
- protected/private IP suppression to avoid blocking trusted local traffic
- GUI dashboard for live monitoring
- API bridge for management and integration
- audit logging, threat intel enrichment, and policy profiles
- structured event export for future SIEM/SOC-style integration

---

## Project goal

The main goal of this project is to build a **working IPS module prototype** that:

1. detects suspicious traffic from live network activity  
2. responds with host-side mitigation actions  
3. remains structured enough to be integrated into a bigger security platform later  

This is not meant to replace enterprise security products, but it is a serious working academic module with real monitoring and real mitigation logic.

---

## Current working capabilities

- captures live traffic in real time
- performs live ML/DL-based prediction
- detects suspicious and zero-day-like traffic patterns
- monitors and logs suspicious activity
- blocks suspicious IPs using Windows Firewall
- throttles selected traffic using Windows QoS policies
- protects local/private IPs from unsafe auto-blocking
- provides a GUI dashboard for live inspection
- supports a small API layer for status and control

---

## Scope and honesty notes

This project performs **live prediction on network traffic** using machine learning and deep learning.

At the same time, this repository is presented honestly within its current scope.

This version does **not** claim:

- guaranteed zero-day prevention in every case
- full Android or iOS protection
- finished enterprise security appliance status
- line-rate inline IPS behavior like mature Suricata or Snort deployments
- perfect certainty in every live prediction

The ML/DL pipeline works on live traffic and provides useful real-time detection signals, but results can still include false positives and should not be treated as absolute forensic truth.

---

## Technologies used

- **Python**
- **Scapy**
- **Scikit-learn**
- **PyTorch**
- **PyQt5**
- **Flask**
- **Windows Firewall**
- **Windows QoS Policy**

---

## Project structure

```text
ips-modules-1.1/
├── main.py
├── requirements.txt
├── pyproject.toml
├── README.md
├── LICENSE
├── .gitignore
├── configs/
├── data/
├── deploy/
├── docs/
├── ips/
│   ├── engine.py
│   ├── api/
│   ├── core/
│   ├── gui/
│   ├── integrations/
│   ├── platform/
│   └── utils/
├── logs/
├── models/
├── quarantine/
├── scripts/
└── tests/
