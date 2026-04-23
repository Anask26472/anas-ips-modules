from __future__ import annotations

import subprocess


def block(ip: str) -> None:
    subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)


def unblock(ip: str) -> None:
    subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
