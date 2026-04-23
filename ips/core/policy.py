from __future__ import annotations

from dataclasses import dataclass

from ips.core.profile_store import ProfileStore
from ips.utils.config import DEFAULT_BLOCK_TTL_SECONDS, MAX_BLOCKED_IPS


@dataclass
class ActionDecision:
    action: str
    block_ttl: int | None = None
    requires_review: bool = False


class PolicyEngine:
    """Small policy layer between detection and response."""

    def __init__(
        self,
        default_block_ttl: int | None = None,
        max_blocked_ips: int | None = None,
    ):
        self.profile_store = ProfileStore()
        active = self.profile_store.active_profile()

        # explicit constructor values should win over profile values
        if default_block_ttl is None:
            self.default_block_ttl = int(
                active.get("default_block_ttl", DEFAULT_BLOCK_TTL_SECONDS)
            )
        else:
            self.default_block_ttl = int(default_block_ttl)

        if max_blocked_ips is None:
            self.max_blocked_ips = int(
                active.get("max_blocked_ips", MAX_BLOCKED_IPS)
            )
        else:
            self.max_blocked_ips = int(max_blocked_ips)

    def decide(self, result: dict, blocked_count: int) -> ActionDecision:
        action = result.get("action", "allow")
        label = result.get("label", "normal")
        score = float(result.get("score", 0.0) or 0.0)

        if action == "block":
            ttl = self.default_block_ttl

            if label in {"dos", "probe"} and score >= 0.95:
                ttl = max(ttl, 1800)

            if blocked_count >= self.max_blocked_ips:
                return ActionDecision(action="monitor", requires_review=True)

            return ActionDecision(action="block", block_ttl=ttl)

        if action == "throttle":
            return ActionDecision(
                action="throttle",
                block_ttl=300 if score >= 0.9 else None,
            )

        if label in {"anomaly", "zero_day_like"}:
            return ActionDecision(action="monitor", requires_review=True)

        return ActionDecision(action=action)

    def activate_profile(self, name: str) -> bool:
        ok = self.profile_store.activate(name)
        if ok:
            active = self.profile_store.active_profile()
            self.default_block_ttl = int(
                active.get("default_block_ttl", self.default_block_ttl)
            )
            self.max_blocked_ips = int(
                active.get("max_blocked_ips", self.max_blocked_ips)
            )
        return ok

    def profiles(self) -> dict:
        return self.profile_store.list_profiles()

    def summary(self) -> dict:
        return {
            "active_profile": self.profile_store.active_name(),
            "default_block_ttl": self.default_block_ttl,
            "max_blocked_ips": self.max_blocked_ips,
            "profiles": list(self.profile_store.list_profiles().get("profiles", {}).keys()),
        }