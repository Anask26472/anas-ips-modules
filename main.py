from __future__ import annotations

import argparse
import sys
import threading

# IMPORTANT:
# engine/torch path ko PyQt se pehle load hone do
from ips.engine import IPSEngine
from ips.utils.logger import get_logger

log = get_logger("main")


def main() -> None:
    parser = argparse.ArgumentParser(description="ML-assisted IPS module")
    parser.add_argument("--headless", action="store_true", help="Run engine without GUI")
    parser.add_argument("--bridge", action="store_true", help="Start management API bridge")
    args = parser.parse_args()

    # create engine BEFORE importing any PyQt/dashboard code
    engine = IPSEngine(start_bridge=args.bridge)

    if args.headless:
        engine.start()
        log.info("headless engine started; press Ctrl+C to stop")
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            engine.stop()
        return

    # import PyQt and dashboard only after engine is created
    from PyQt5.QtWidgets import QApplication
    from ips.gui.dashboard import IPSDashboard

    app = QApplication(sys.argv)
    window = IPSDashboard(engine)
    window.show()
    log.info("dashboard launched")
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()