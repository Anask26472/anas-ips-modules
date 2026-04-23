# Suricata control-plane path

This module is designed to work well as a Python control plane next to Suricata.

## Recommended split
- Suricata: inline packet path, deep protocol parsing, drop/reject rules
- This module: management API, ML enrichment, policy, audit, reporting, local dashboards

## Current support
- import Suricata EVE alerts from file
- store recent imported alerts in memory
- expose status over the bridge
