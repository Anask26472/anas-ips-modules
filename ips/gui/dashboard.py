from __future__ import annotations

import threading
from datetime import datetime

from PyQt5.QtCore import QObject, pyqtSignal
from PyQt5.QtGui import QColor, QFont
from PyQt5.QtWidgets import (
    QFrame,
    QHeaderView,
    QLabel,
    QHBoxLayout,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ips.utils.logger import get_logger

log = get_logger(__name__)


class ThreatSignal(QObject):
    new_threat = pyqtSignal(object)


class IPSDashboard(QMainWindow):
    def __init__(self, engine):
        super().__init__()
        self.engine = engine
        self.signal = ThreatSignal()
        self.signal.new_threat.connect(self._on_threat)
        self.engine.set_callback(self.signal.new_threat.emit)
        self._engine_thread = None
        self.threat_count = 0
        self.blocked_count = 0
        self._build_ui()

    def _build_ui(self):
        self.setWindowTitle("IPS Module")
        self.setMinimumSize(1000, 620)
        self.setStyleSheet("background-color: #1e1e2e; color: #cdd6f4;")

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setSpacing(10)
        layout.setContentsMargins(16, 16, 16, 16)

        title = QLabel("IPS — ML-Assisted Intrusion Monitoring")
        title.setFont(QFont("Arial", 15, QFont.Bold))
        title.setStyleSheet("color: #89b4fa; padding: 4px 0;")
        layout.addWidget(title)

        stats_row = QHBoxLayout()
        self.card_threats = self._card("Threats Detected", "0", "#f38ba8")
        self.card_blocked = self._card("IPs Blocked", "0", "#fab387")
        self.card_unknown = self._card("Unknown / AE", "0", "#cba6f7")
        self.card_status = self._card("Status", "Idle", "#a6e3a1")
        for frame, _ in [self.card_threats, self.card_blocked, self.card_unknown, self.card_status]:
            stats_row.addWidget(frame)
        layout.addLayout(stats_row)

        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["Time", "Source IP", "Type", "Score", "Layer", "Action"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setStyleSheet(
            "QTableWidget {background: #181825; border: none; gridline-color: #313244;}"
            "QHeaderView::section {background: #313244; color: #cdd6f4; padding: 6px; border: none; font-weight: bold;}"
            "QTableWidget::item {padding: 4px 8px;}"
        )
        layout.addWidget(self.table)

        btn_row = QHBoxLayout()
        self.btn_start = QPushButton("▶ Start Monitoring")
        self.btn_stop = QPushButton("■ Stop")
        self.btn_clear = QPushButton("🗑 Clear")
        self.btn_perf = QPushButton("📊 Performance")

        style = (
            "QPushButton {background: #313244; color: #cdd6f4; border: 1px solid #45475a; border-radius: 6px; padding: 6px 16px; font-size: 13px; min-height: 32px;}"
            "QPushButton:hover { background: #45475a; }"
            "QPushButton:pressed { background: #585b70; }"
        )
        for btn in [self.btn_start, self.btn_stop, self.btn_clear, self.btn_perf]:
            btn.setStyleSheet(style)

        self.btn_start.clicked.connect(self.start_monitoring)
        self.btn_stop.clicked.connect(self.stop_monitoring)
        self.btn_clear.clicked.connect(self._clear_table)
        self.btn_perf.clicked.connect(self._show_performance)

        btn_row.addWidget(self.btn_start)
        btn_row.addWidget(self.btn_stop)
        btn_row.addStretch()
        btn_row.addWidget(self.btn_perf)
        btn_row.addWidget(self.btn_clear)
        layout.addLayout(btn_row)

    def _card(self, label, value, color):
        frame = QFrame()
        frame.setStyleSheet("background:#181825; border-radius:8px; padding:8px;")
        vbox = QVBoxLayout(frame)
        lbl = QLabel(label)
        lbl.setStyleSheet("color:#6c7086; font-size:11px;")
        val = QLabel(value)
        val.setStyleSheet(f"color:{color}; font-size:22px; font-weight:bold;")
        vbox.addWidget(lbl)
        vbox.addWidget(val)
        return frame, val

    def start_monitoring(self):
        if self.engine.running:
            return
        self.engine.start()
        self.card_status[1].setText("Active")
        self.card_status[1].setStyleSheet("color: #a6e3a1; font-size: 22px; font-weight: bold;")
        log.info("monitoring started")

    def stop_monitoring(self):
        self.engine.stop()
        self.card_status[1].setText("Stopped")
        self.card_status[1].setStyleSheet("color:#f38ba8; font-size:22px; font-weight:bold;")
        log.info("monitoring stopped")

    def _on_threat(self, data):
        row = self.table.rowCount()
        self.table.insertRow(row)
        label = data.get("label", "unknown")
        score = data.get("score", 0.0)
        layer = data.get("layer", "-")
        action = data.get("action", "-")
        src = data.get("src_ip", "-")
        when = data.get("time") or datetime.now().strftime("%H:%M:%S")

        colors = {
            "dos": "#f38ba8",
            "probe": "#f9e2af",
            "r2l": "#fab387",
            "u2r": "#f38ba8",
            "anomaly": "#fab387",
            "zero_day_like": "#cba6f7",
        }
        color = colors.get(label, "#cdd6f4")

        for col, text in enumerate([when, src, label.upper(), str(round(float(score), 4)), layer, action.upper()]):
            item = QTableWidgetItem(text)
            item.setForeground(QColor(color))
            self.table.setItem(row, col, item)

        self.threat_count += 1
        self.card_threats[1].setText(str(self.threat_count))

        if label == "zero_day_like":
            current = int(self.card_unknown[1].text() or 0)
            self.card_unknown[1].setText(str(current + 1))

        if action == "block":
            self.blocked_count += 1
            self.card_blocked[1].setText(str(self.blocked_count))

        self.table.scrollToBottom()

    def _clear_table(self):
        self.table.setRowCount(0)

    def _show_performance(self):
        report = self.engine.get_performance()
        msg = (
            f"Uptime (min): {report['uptime_minutes']}\n"
            f"Total packets: {report['total_packets']}\n"
            f"Threats: {report['threats_detected']}\n"
            f"Blocked: {report['blocked']}\n"
            f"Avg response ms: {report['avg_response_ms']}"
        )
        QMessageBox.information(self, "Performance", msg)
