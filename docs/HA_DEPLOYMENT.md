# HA deployment notes

This repository now includes HA status scaffolding and heartbeat tracking.

## Important honesty
This is not a full active-active or active-passive packet-path cluster.
It is a control-plane starting point for:
- node identity
- fail-open / fail-close mode tracking
- peer heartbeats
- management visibility

## Real HA later needs
- traffic failover design
- shared policy distribution
- node health checks
- external load balancer or inline redundancy
- tested rollback/fail mode behavior
