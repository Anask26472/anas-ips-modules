from __future__ import annotations

from scapy.all import AsyncSniffer
from ips.utils.config import DEFAULT_INTERFACE
from ips.utils.logger import get_logger

log = get_logger(__name__)


class LiveSniffer:
    def __init__(self, interface: str | None = None):
        self.interface = interface or DEFAULT_INTERFACE
        self._sniffer: AsyncSniffer | None = None

    def start(self, callback) -> None:
        if self._sniffer and self._sniffer.running:
            log.info("sniffer already running")
            return
        kwargs = {"prn": callback, "store": False}
        if self.interface:
            kwargs["iface"] = self.interface
        self._sniffer = AsyncSniffer(**kwargs)
        self._sniffer.start()
        log.info(f"sniffer started on interface: {self.interface or 'auto'}")

    def stop(self) -> None:
        if self._sniffer and self._sniffer.running:
            self._sniffer.stop()
            log.info("sniffer stopped")
