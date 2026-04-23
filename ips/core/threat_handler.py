from __future__ import annotations

import ipaddress
import json
import platform
import time
from typing import Dict


from ips.platform import linux, windows
from ips.utils.config import (
    BLOCK_STATE_FILE,
    ENABLE_BLOCKING,
    MAX_BLOCKED_IPS,
    WHITELISTED_IPS,
)
from ips.utils.logger import get_logger

log = get_logger(__name__)


class ThreatHandler:
    def __init__(self):
        self.blocked_ips: Dict[str, dict] = {}
        self.system = platform.system().lower()
        self.throttled_until: Dict[str, float] = {}

        # stop repeated spam and repeated failed block attempts
        self.last_event_time: Dict[str, float] = {}
        self.failed_block_until: Dict[str, float] = {}

        self._load_state()

    def respond(self, features: dict, result: dict, policy=None) -> bool:
        action = result.get("action", "allow")
        ip = features.get("src_ip")
        label = result.get("label", "unknown")

        if not ip:
            return False

        # private / trusted / protected IPs ke liye action suppress
        if self._should_skip(ip):
            if action == "block":
                if self._can_log(f"skip_block:{ip}", cooldown=15):
                    log.info(f"skipping block for protected/invalid IP: {ip}")
            elif action in {"throttle", "monitor"}:
                if self._can_log(f"protected_notice:{ip}", cooldown=20):
                    log.info(f"protected/private IP observed, action suppressed: {ip} | {label}")
            return False

        if action == "block":
            ttl = None
            if policy is not None:
                ttl = getattr(policy, "block_ttl", None)
            return self.block_ip(ip, reason=label, ttl=ttl)

        if action == "throttle":
            throttle_ttl = 30
            if policy is not None:
                throttle_ttl = getattr(policy, "throttle_ttl", 30)

            return self.throttle_ip(
                ip,
                reason=label,
                bits_per_second=1_000_000,
                ttl=throttle_ttl,
            )

        if action == "monitor":
            if self._can_log(f"monitor:{ip}", cooldown=5):
                log.warning(f"MONITOR {ip} | {label}")
            return False

        return False

    def block_ip(self, ip: str, reason: str = "suspicious", ttl: int | None = None) -> bool:
        if not ENABLE_BLOCKING:
            log.warning("blocking disabled by configuration")
            return False

        if self._should_skip(ip):
            if self._can_log(f"skip_block:{ip}", cooldown=15):
                log.info(f"skipping block for protected/invalid IP: {ip}")
            return False

        if self._block_in_cooldown(ip):
            if self._can_log(f"block_cooldown:{ip}", cooldown=10):
                log.warning(f"recent block failure cooldown active for {ip}, skipping retry")
            return False

        if len(self.blocked_ips) >= MAX_BLOCKED_IPS and ip not in self.blocked_ips:
            log.warning("max blocked IP limit reached; refusing new block")
            return False

        if ip in self.blocked_ips:
            return True

        try:
            # optional cleanup of old rule before adding again
            self._best_effort_remove_old_rule(ip)

            if self.system == "windows":
                windows.block(ip)
            elif self.system == "linux":
                linux.block(ip)
            else:
                log.warning(f"firewall block not implemented for platform: {self.system}")
                return False

            expires_at = time.time() + ttl if ttl else None
            self.blocked_ips[ip] = {
                "blocked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "reason": reason,
                "expires_at": expires_at,
                "ttl_seconds": ttl,
            }

            # successful block -> remove failure cooldown
            self.failed_block_until.pop(ip, None)

            self._save_state()
            log.warning(f"BLOCKED {ip} | reason={reason} | ttl={ttl}")
            return True

        except Exception as exc:
            # don't hammer the same failed command again and again
            self.failed_block_until[ip] = time.time() + 30
            log.error(f"failed to block {ip}: {exc}")
            return False
    def throttle_ip(
        self,
        ip: str,
        reason: str = "suspicious",
        bits_per_second: int = 1_000_000,
        ttl: int = 30,
    ) -> bool:
        if self._should_skip(ip):
            if self._can_log(f"skip_throttle:{ip}", cooldown=20):
                log.info(f"skipping throttle for protected/invalid IP: {ip}")
            return False

        now = time.time()
        until = self.throttled_until.get(ip)
        if until and now < until:
            return True

        try:
            if self.system == "windows":
                windows.throttle(ip, bits_per_second=bits_per_second)
            elif self.system == "linux":
                log.warning(f"THROTTLE requested for {ip} | linux throttle not implemented yet | {reason}")
                return False
            else:
                log.warning(f"THROTTLE requested for {ip} | unsupported platform | {reason}")
                return False

            self.throttled_until[ip] = now + ttl
            log.warning(f"THROTTLE applied for {ip} | {bits_per_second} bps | ttl={ttl} | {reason}")
            return True

        except Exception as exc:
            log.error(f"failed to throttle {ip}: {exc}")
            return False

    def expire_throttles(self) -> list[str]:
        now = time.time()
        expired = []

        for ip, until in list(self.throttled_until.items()):
            if now >= until:
                try:
                    if self.system == "windows":
                        windows.unthrottle(ip)
                    self.throttled_until.pop(ip, None)
                    expired.append(ip)
                    log.info(f"unthrottled {ip}")
                except Exception as exc:
                    log.error(f"failed to unthrottle {ip}: {exc}")

        return expired
    def unblock_ip(self, ip: str) -> bool:
        if ip not in self.blocked_ips:
            return True

        try:
            if self.system == "windows":
                windows.unblock(ip)
            elif self.system == "linux":
                linux.unblock(ip)
            else:
                return False

            self.blocked_ips.pop(ip, None)
            self.failed_block_until.pop(ip, None)
            self._save_state()
            log.info(f"unblocked {ip}")
            return True

        except Exception as exc:
            # protected/private IPs ke liye stale local state clear kar do
            if self._should_skip(ip):
                self.blocked_ips.pop(ip, None)
                self.failed_block_until.pop(ip, None)
                self._save_state()
                if self._can_log(f"stale_unblock:{ip}", cooldown=30):
                    log.info(f"cleared stale blocked state for protected/private IP: {ip}")
                return True

            log.error(f"failed to unblock {ip}: {exc}")
            return False
    def expire_blocks(self) -> list[str]:
        now = time.time()
        expired = []

        for ip, data in list(self.blocked_ips.items()):
            expires_at = data.get("expires_at")
            if expires_at and now >= float(expires_at):
                if self.unblock_ip(ip):
                    expired.append(ip)

        return expired
    
    def clear_throttles(self) -> int:
        count = 0

        for ip in list(self.throttled_until):
            try:
                if self.system == "windows":
                    windows.unthrottle(ip)
                self.throttled_until.pop(ip, None)
                count += 1
                log.info(f"cleared throttle for {ip}")
            except Exception as exc:
                log.error(f"failed to clear throttle for {ip}: {exc}")

        return count
    def clear_all(self) -> int:
        count = 0

        for ip in list(self.blocked_ips):
            if self.unblock_ip(ip):
                count += 1

        count += self.clear_throttles()
        return count

    def list_blocked_ips(self) -> list[str]:
        return sorted(self.blocked_ips)

    def blocked_details(self) -> dict:
        return dict(self.blocked_ips)

    def _should_skip(self, ip: str) -> bool:
        if ip in WHITELISTED_IPS:
            return True

        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return True

        if (
            addr.is_loopback
            or addr.is_multicast
            or addr.is_unspecified
            or addr.is_link_local
            or addr.is_private
        ):
            return True

        return False

    def _can_log(self, key: str, cooldown: int = 5) -> bool:
        now = time.time()
        last = self.last_event_time.get(key, 0)

        if now - last >= cooldown:
            self.last_event_time[key] = now
            return True

        return False

    def _block_in_cooldown(self, ip: str) -> bool:
        until = self.failed_block_until.get(ip)
        if until is None:
            return False
        return time.time() < until

    def _best_effort_remove_old_rule(self, ip: str) -> None:
        try:
            if self.system == "windows":
                windows.unblock(ip)
            elif self.system == "linux":
                linux.unblock(ip)
        except Exception:
            # ignore cleanup failure, real add call will decide success/failure
            pass

    def _load_state(self) -> None:
        if not BLOCK_STATE_FILE.exists():
            return

        try:
            payload = json.loads(BLOCK_STATE_FILE.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                cleaned = {}
                for ip, data in payload.items():
                    if not self._should_skip(ip):
                        cleaned[ip] = data
                self.blocked_ips = cleaned
            else:
                self.blocked_ips = {}
        except Exception:
            self.blocked_ips = {}
    def _save_state(self) -> None:
        BLOCK_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        BLOCK_STATE_FILE.write_text(
            json.dumps(self.blocked_ips, indent=2),
            encoding="utf-8",
        )