from __future__ import annotations

import subprocess


def _run(cmd: list[str]) -> None:
    subprocess.run(cmd, check=True, capture_output=True, text=True)


def _run_powershell(command: str) -> None:
    _run([
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        command,
    ])


def _rule_name(ip: str) -> str:
    return f"IPS_BLOCK_{ip}"


def _qos_name(ip: str) -> str:
    safe = ip.replace(".", "_").replace(":", "_")
    return f"IPS_QOS_{safe}"


def block(ip: str) -> None:
    _run([
        "netsh",
        "advfirewall",
        "firewall",
        "add",
        "rule",
        f"name={_rule_name(ip)}",
        "dir=in",
        "action=block",
        f"remoteip={ip}",
    ])


def unblock(ip: str) -> None:
    _run([
        "netsh",
        "advfirewall",
        "firewall",
        "delete",
        "rule",
        f"name={_rule_name(ip)}",
    ])


def throttle(ip: str, bits_per_second: int = 1_000_000) -> None:
    name = _qos_name(ip)

    # best-effort cleanup first
    try:
        unthrottle(ip)
    except Exception:
        pass

    ps = (
        f'Remove-NetQosPolicy -Name "{name}" '
        f'-PolicyStore ActiveStore -Confirm:$False -ErrorAction SilentlyContinue; '
        f'New-NetQosPolicy -Name "{name}" '
        f'-IPDstPrefixMatchCondition "{ip}/32" '
        f'-ThrottleRateActionBitsPerSecond {bits_per_second} '
        f'-PolicyStore ActiveStore'
    )
    _run_powershell(ps)


def unthrottle(ip: str) -> None:
    name = _qos_name(ip)
    ps = (
        f'Remove-NetQosPolicy -Name "{name}" '
        f'-PolicyStore ActiveStore -Confirm:$False'
    )
    _run_powershell(ps)