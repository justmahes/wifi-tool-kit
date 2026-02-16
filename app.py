from __future__ import annotations

import csv
import ipaddress
import json
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import winsound
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import (
    QDateTime,
    QObject,
    QPropertyAnimation,
    QEasingCurve,
    QThread,
    QTimer,
    Qt,
    QTime,
    Signal,
)
from PySide6.QtGui import QAction, QBrush, QColor, QFont, QPainter, QPen
from PySide6.QtCharts import QChart, QChartView, QLineSeries, QValueAxis
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFormLayout,
    QGraphicsOpacityEffect,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QPushButton,
    QFileDialog,
    QGridLayout,
    QSizePolicy,
    QSpinBox,
    QStyle,
    QSystemTrayIcon,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QTimeEdit,
    QVBoxLayout,
    QWidget,
)


def subprocess_no_window_kwargs() -> dict:
    if sys.platform != "win32":
        return {}
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    return {
        "creationflags": subprocess.CREATE_NO_WINDOW,
        "startupinfo": startupinfo,
    }


class Worker(QObject):
    finished = Signal(object)
    error = Signal(str)

    def __init__(self, func):
        super().__init__()
        self.func = func

    def run(self):
        try:
            result = self.func()
        except Exception as exc:  # noqa: BLE001
            self.error.emit(str(exc))
            return
        self.finished.emit(result)


def run_ping(host: str, count: int = 4, timeout_ms: int = 1000) -> dict:
    cmd = ["ping", "-n", str(count), "-w", str(timeout_ms), host]
    completed = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=(count * timeout_ms / 1000 + 2),
        check=False,
        **subprocess_no_window_kwargs(),
    )
    output = completed.stdout + completed.stderr

    loss_match = re.search(r"Lost = \d+\s+\((\d+)% loss\)", output)
    avg_match = re.search(r"Average = (\d+)ms", output)

    loss_percent = int(loss_match.group(1)) if loss_match else None
    avg_ms = int(avg_match.group(1)) if avg_match else None

    return {
        "host": host,
        "avg_ms": avg_ms,
        "loss_percent": loss_percent,
        "raw": output.strip(),
    }


def parse_target_list(text: str) -> list[str]:
    parts = [part.strip() for part in re.split(r"[,\s]+", text or "") if part.strip()]
    seen: set[str] = set()
    targets: list[str] = []
    for part in parts:
        if part in seen:
            continue
        seen.add(part)
        targets.append(part)
    return targets


def run_multi_ping(hosts: list[str], count: int = 4, timeout_ms: int = 1000) -> list[dict]:
    results = []
    for host in hosts:
        results.append(run_ping(host, count=count, timeout_ms=timeout_ms))
    return results


def run_monitor_ping(
    base_targets: list[str],
    include_gateway: bool,
    include_dns: bool,
    timeout_ms: int = 1000,
) -> dict:
    targets = list(base_targets)
    gateway = None
    if include_gateway:
        gateway = get_default_gateway()
        if gateway:
            targets.append(gateway)
    if include_dns:
        targets.append("8.8.8.8")
    targets = parse_target_list(",".join(targets))
    if not targets:
        raise RuntimeError("No targets configured.")
    results = run_multi_ping(targets, count=1, timeout_ms=timeout_ms)
    return {
        "targets": targets,
        "gateway": gateway,
        "dns": "8.8.8.8" if include_dns else None,
        "results": results,
    }


def run_command_capture(cmd: list[str], timeout_s: int = 20) -> dict:
    completed = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        check=False,
        **subprocess_no_window_kwargs(),
    )
    return {
        "cmd": " ".join(cmd),
        "returncode": completed.returncode,
        "stdout": (completed.stdout or "").strip(),
        "stderr": (completed.stderr or "").strip(),
    }


def play_alert_sound():
    try:
        winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
    except RuntimeError:
        pass


def get_app_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.argv[0]).resolve().parent
    return Path(__file__).resolve().parent


def download_oui_database(dest_path: Path) -> None:
    url = "https://standards-oui.ieee.org/oui/oui.csv"
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "WiFiToolkit/1.0 (+https://example.local)",
            "Accept": "text/csv,*/*;q=0.1",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
        dest_path.write_bytes(response.read())


def load_oui_database(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    oui_map: dict[str, str] = {}
    with open(path, "r", encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        for row in reader:
            if len(row) < 3 or row[0].lower() == "registry":
                continue
            assignment = re.sub(r"[^0-9A-Fa-f]", "", row[1])
            if len(assignment) < 6:
                continue
            oui = assignment[:6].upper()
            organization = row[2].strip()
            if oui and organization:
                oui_map[oui] = organization
    return oui_map


def normalize_oui(mac: str) -> str | None:
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", mac)
    if len(cleaned) < 6:
        return None
    return cleaned[:6].upper()


def resolve_hostname(ip: str) -> str | None:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except OSError:
        return None


def get_default_subnet() -> str | None:
    completed = subprocess.run(
        ["ipconfig"],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
        **subprocess_no_window_kwargs(),
    )
    ip_value = None
    ip_pattern = re.compile(r"IPv4 Address[^\d]*([\d\.]+)")
    mask_pattern = re.compile(r"Subnet Mask[^\d]*([\d\.]+)")

    for line in completed.stdout.splitlines():
        ip_match = ip_pattern.search(line)
        if ip_match:
            ip_value = ip_match.group(1)
            continue

        mask_match = mask_pattern.search(line)
        if mask_match and ip_value:
            mask_value = mask_match.group(1)
            try:
                network = ipaddress.ip_network(f"{ip_value}/{mask_value}", strict=False)
            except ValueError:
                ip_value = None
                continue
            if not ip_value.startswith("169.254."):
                return f"{network.network_address}/{network.prefixlen}"
            ip_value = None

    return None


def get_default_gateway() -> str | None:
    completed = subprocess.run(
        ["ipconfig"],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
        **subprocess_no_window_kwargs(),
    )
    gw_pattern = re.compile(r"Default Gateway[^\d]*([\d\.]+)")
    for line in completed.stdout.splitlines():
        match = gw_pattern.search(line)
        if match:
            gateway = match.group(1)
            if gateway and gateway != "0.0.0.0":
                return gateway
    return None


def parse_netsh_interfaces(output: str) -> list[dict[str, str]]:
    interfaces: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in output.splitlines():
        if not line.strip():
            if current:
                interfaces.append(current)
                current = {}
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        current[key.strip()] = value.strip()
    if current:
        interfaces.append(current)
    return interfaces


def get_wifi_details() -> dict[str, str]:
    completed = subprocess.run(
        ["netsh", "wlan", "show", "interfaces"],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
        **subprocess_no_window_kwargs(),
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "netsh failed")

    interfaces = parse_netsh_interfaces(completed.stdout)
    if not interfaces:
        raise RuntimeError("No Wi-Fi interfaces found.")

    connected = next(
        (item for item in interfaces if item.get("State", "").lower() == "connected"),
        None,
    )
    return connected or interfaces[0]


def format_speedtest_text(result: dict) -> str:
    def format_number(value: float | int | None, unit: str) -> str:
        if value is None:
            return "-"
        return f"{value:.2f} {unit}"

    lines = [
        f"Source: {result.get('source', '-')}",
        f"Ping: {format_number(result.get('ping_ms'), 'ms')}",
        f"Download: {format_number(result.get('download_mbps'), 'Mbps')}",
        f"Upload: {format_number(result.get('upload_mbps'), 'Mbps')}",
    ]

    packet_loss = result.get("packet_loss")
    if packet_loss is not None:
        try:
            lines.append(f"Packet loss: {float(packet_loss):.2f}%")
        except (TypeError, ValueError):
            lines.append(f"Packet loss: {packet_loss}%")

    isp = result.get("isp")
    if isp:
        lines.append(f"ISP: {isp}")

    server_name = result.get("server_name")
    server_location = result.get("server_location")
    if server_name or server_location:
        if server_name and server_location:
            lines.append(f"Server: {server_name} ({server_location})")
        else:
            lines.append(f"Server: {server_name or server_location}")

    result_url = result.get("result_url")
    if result_url:
        lines.append(f"Result: {result_url}")

    return "\n".join(lines)


def run_speedtest(cancel_event: threading.Event | None = None, timeout_s: int = 120) -> dict:
    cancel_event = cancel_event or threading.Event()
    speedtest_path = shutil.which("speedtest")
    speedtest_cli_path = shutil.which("speedtest-cli")

    if speedtest_path:
        cmd = [
            speedtest_path,
            "--accept-license",
            "--accept-gdpr",
            "-f",
            "json",
        ]
        source = "speedtest"
    elif speedtest_cli_path:
        cmd = [speedtest_cli_path, "--json"]
        source = "speedtest-cli"
    else:
        raise RuntimeError("speedtest tool not found. Install speedtest or speedtest-cli.")

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        **subprocess_no_window_kwargs(),
    )
    start = time.monotonic()
    while process.poll() is None:
        if cancel_event.is_set():
            process.kill()
            raise RuntimeError("Speed test cancelled.")
        if time.monotonic() - start > timeout_s:
            process.kill()
            raise RuntimeError("Speed test timed out.")
        time.sleep(0.2)

    stdout, stderr = process.communicate()
    raw = (stdout or "").strip() or (stderr or "").strip()
    if process.returncode != 0:
        raise RuntimeError(raw or f"{source} failed")

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{source} output is not valid JSON: {raw[:200]}") from exc

    if source == "speedtest":
        ping_ms = payload.get("ping", {}).get("latency")
        download_mbps = payload.get("download", {}).get("bandwidth", 0) * 8 / 1_000_000
        upload_mbps = payload.get("upload", {}).get("bandwidth", 0) * 8 / 1_000_000
        packet_loss = payload.get("packetLoss")
        isp = payload.get("isp")
        server = payload.get("server", {}) or {}
        server_name = server.get("name")
        server_location = server.get("location")
        result_url = (payload.get("result") or {}).get("url")
    else:
        ping_ms = payload.get("ping")
        download_mbps = payload.get("download", 0) / 1_000_000
        upload_mbps = payload.get("upload", 0) / 1_000_000
        packet_loss = payload.get("packetLoss")
        client = payload.get("client", {}) or {}
        isp = client.get("isp") or payload.get("isp")
        server = payload.get("server", {}) or {}
        server_name = server.get("sponsor") or server.get("name")
        server_location = server.get("country") or server.get("location")
        result_url = payload.get("share")

    raw_pretty = json.dumps(payload, indent=2, ensure_ascii=True)

    return {
        "source": source,
        "ping_ms": ping_ms,
        "download_mbps": download_mbps,
        "upload_mbps": upload_mbps,
        "packet_loss": packet_loss,
        "isp": isp,
        "server_name": server_name,
        "server_location": server_location,
        "result_url": result_url,
        "raw": raw_pretty,
    }


def run_arp_scan(
    subnet_cidr: str | None = None,
    timeout_ms: int = 250,
    resolve_names: bool = True,
    oui_db: dict[str, str] | None = None,
) -> list[dict]:
    if subnet_cidr:
        try:
            network = ipaddress.ip_network(subnet_cidr, strict=False)
        except ValueError as exc:
            raise RuntimeError(f"Invalid subnet: {subnet_cidr}") from exc

        host_count = max(int(network.num_addresses) - 2, 0)
        if host_count > 1024:
            raise RuntimeError("Subnet too large. Use /24 or smaller.")

        def ping_host(address: str) -> None:
            subprocess.run(
                ["ping", "-n", "1", "-w", str(timeout_ms), address],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                **subprocess_no_window_kwargs(),
            )

        hosts = [str(host) for host in network.hosts()]
        if hosts:
            worker_count = min(100, len(hosts))
            with ThreadPoolExecutor(max_workers=worker_count) as executor:
                for host in hosts:
                    executor.submit(ping_host, host)
            time.sleep(0.5)

    completed = subprocess.run(
        ["arp", "-a"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
        **subprocess_no_window_kwargs(),
    )
    output = completed.stdout
    devices = []
    pattern = re.compile(
        r"(\d+\.\d+\.\d+\.\d+)\s+"
        r"([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+"
        r"(\w+)",
    )

    for line in output.splitlines():
        match = pattern.search(line)
        if match:
            ip, mac, entry_type = match.groups()
            devices.append(
                {
                    "ip": ip,
                    "mac": mac,
                    "type": entry_type,
                    "hostname": None,
                    "vendor": None,
                }
            )

    if not devices:
        return devices

    previous_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(1.0)
    try:
        for device in devices:
            if resolve_names:
                device["hostname"] = resolve_hostname(device["ip"]) or ""
            if oui_db:
                oui = normalize_oui(device["mac"])
                if oui and oui in oui_db:
                    device["vendor"] = oui_db[oui]
                else:
                    device["vendor"] = ""
            else:
                device["vendor"] = ""
    finally:
        socket.setdefaulttimeout(previous_timeout)

    return devices


def ping_host_once(host: str, timeout_ms: int = 250) -> None:
    subprocess.run(
        ["ping", "-n", "1", "-w", str(timeout_ms), host],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        **subprocess_no_window_kwargs(),
    )


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Wi-Fi Toolkit")
        self.resize(900, 600)

        self.monitor_history: list[dict] = []
        self.monitor_running = False
        self.ping_in_flight = False
        self.speedtest_in_flight = False
        self.speedtest_cancel_event: threading.Event | None = None
        self.active_workers: list[tuple[QThread, Worker]] = []
        self.last_latency_ms: int | None = None
        self.device_scan_in_flight = False
        self.device_scan_partial = False
        self.device_history: dict[str, dict] = {}
        self.current_device_keys: set[str] = set()
        self.devices_table_updating = False
        self.sample_index = 0
        self.max_points = 120
        self.last_alert_time = 0.0
        self.tray_notified = False
        self.monitor_next_run_at: float | None = None
        self.devices_next_run_at: float | None = None
        self.monitor_targets_current: list[str] = []
        self.monitor_primary_target: str | None = None
        self.monitor_gateway_target: str | None = None
        self.monitor_dns_target: str | None = None
        self.dark_mode_enabled = True

        self.oui_path = get_app_dir() / "data" / "oui.csv"
        self.oui_db = load_oui_database(self.oui_path)
        self.device_notes_path = get_app_dir() / "data" / "device_notes.json"
        self.device_notes = self.load_device_notes()
        self.speed_raw_json_text = ""

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.queue_ping)
        self.devices_timer = QTimer(self)
        self.devices_timer.timeout.connect(self.auto_scan_devices)
        self.monitor_countdown_timer = QTimer(self)
        self.monitor_countdown_timer.timeout.connect(self.update_monitor_countdown)
        self.devices_countdown_timer = QTimer(self)
        self.devices_countdown_timer.timeout.connect(self.update_devices_countdown)

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.dashboard_tab = QWidget()
        self.speed_tab = QWidget()
        self.devices_tab = QWidget()
        self.wifi_tab = QWidget()
        self.diagnostics_tab = QWidget()

        self.tabs.addTab(self.dashboard_tab, "Monitor")
        self.tabs.addTab(self.speed_tab, "Speed Test")
        self.tabs.addTab(self.devices_tab, "Devices")
        self.tabs.addTab(self.wifi_tab, "Wi-Fi")
        self.tabs.addTab(self.diagnostics_tab, "Diagnostics")
        self.active_animations: list[QPropertyAnimation] = []
        self.tabs.currentChanged.connect(self.animate_tab_transition)

        self._build_dashboard()
        self._build_speed()
        self._build_devices()
        self._build_wifi()
        self._build_diagnostics()

        self._setup_tray()
        self._apply_theme()

    def _build_dashboard(self):
        layout = QVBoxLayout()
        layout.setSpacing(12)
        layout.setContentsMargins(12, 12, 12, 12)

        header = QVBoxLayout()
        header.setSpacing(2)
        title = QLabel("Monitor")
        title.setProperty("role", "title")
        subtitle = QLabel("Live latency, jitter, loss, alerts, and health score.")
        subtitle.setProperty("role", "subtitle")
        header.addWidget(title)
        header.addWidget(subtitle)
        layout.addLayout(header)

        form = QFormLayout()
        self.host_input = QLineEdit("8.8.8.8")
        self.host_input.setPlaceholderText("e.g. 8.8.8.8, 1.1.1.1")
        self.interval_spin = QSpinBox()
        self.interval_spin.setRange(5, 3600)
        self.interval_spin.setValue(10)
        self.interval_spin.setSuffix(" s")
        form.addRow("Targets:", self.host_input)
        form.addRow("Interval:", self.interval_spin)

        layout.addLayout(form)

        targets_row = QHBoxLayout()
        self.include_gateway_check = QCheckBox("Include gateway")
        self.include_dns_check = QCheckBox("Include 8.8.8.8")
        targets_row.addWidget(self.include_gateway_check)
        targets_row.addWidget(self.include_dns_check)
        targets_row.addStretch()
        layout.addLayout(targets_row)

        button_row = QHBoxLayout()
        self.start_button = QPushButton("Start")
        self.stop_button = QPushButton("Stop")
        self.ping_button = QPushButton("Ping Now")
        self.export_monitor_button = QPushButton("Export CSV")
        button_row.addWidget(self.start_button)
        button_row.addWidget(self.stop_button)
        button_row.addWidget(self.ping_button)
        button_row.addWidget(self.export_monitor_button)
        button_row.addStretch()

        layout.addLayout(button_row)

        status_row = QHBoxLayout()
        self.status_label = QLabel("Idle")
        self.latency_label = QLabel("-")
        self.jitter_label = QLabel("-")
        self.loss_label = QLabel("-")
        self.updated_label = QLabel("-")
        self.next_ping_label = QLabel("-")
        self.latency_label.setProperty("role", "kpi")
        self.jitter_label.setProperty("role", "kpi")
        self.loss_label.setProperty("role", "kpi")
        self.set_status_badge(self.status_label, "idle", "Idle")

        status_row.addWidget(QLabel("Status:"))
        status_row.addWidget(self.status_label)
        status_row.addSpacing(20)
        status_row.addWidget(QLabel("Next ping in:"))
        status_row.addWidget(self.next_ping_label)
        status_row.addSpacing(20)
        status_row.addWidget(QLabel("Avg latency:"))
        status_row.addWidget(self.latency_label)
        status_row.addSpacing(20)
        status_row.addWidget(QLabel("Jitter:"))
        status_row.addWidget(self.jitter_label)
        status_row.addSpacing(20)
        status_row.addWidget(QLabel("Packet loss:"))
        status_row.addWidget(self.loss_label)
        status_row.addSpacing(20)
        status_row.addWidget(QLabel("Last update:"))
        status_row.addWidget(self.updated_label)
        status_row.addStretch()

        layout.addLayout(status_row)

        health_row = QHBoxLayout()
        self.health_score_label = QLabel("-")
        self.root_cause_label = QLabel("-")
        self.health_score_label.setProperty("role", "score")
        health_row.addWidget(QLabel("Health score:"))
        health_row.addWidget(self.health_score_label)
        health_row.addSpacing(20)
        health_row.addWidget(QLabel("Root cause hint:"))
        health_row.addWidget(self.root_cause_label)
        health_row.addStretch()
        layout.addLayout(health_row)

        self.chart = QChart()
        self.chart.setTitle("Latency / Jitter / Loss")
        self.latency_series = QLineSeries(name="Latency (ms)")
        self.jitter_series = QLineSeries(name="Jitter (ms)")
        self.loss_series = QLineSeries(name="Loss (%)")
        self.latency_series.setPen(QPen(QColor("#2563eb"), 2))
        self.jitter_series.setPen(QPen(QColor("#f59e0b"), 2))
        self.loss_series.setPen(QPen(QColor("#ef4444"), 2))
        self.chart.addSeries(self.latency_series)
        self.chart.addSeries(self.jitter_series)
        self.chart.addSeries(self.loss_series)
        self.chart.legend().setAlignment(Qt.AlignBottom)
        self.chart.setBackgroundBrush(QBrush(QColor("#ffffff")))
        self.chart.setBackgroundRoundness(8)

        self.axis_x = QValueAxis()
        self.axis_x.setTitleText("Sample")
        self.axis_x.setLabelFormat("%d")
        self.axis_x.setRange(0, self.max_points)
        self.axis_x.setLabelsColor(QColor("#64748b"))
        self.axis_x.setTitleBrush(QBrush(QColor("#475569")))
        self.chart.addAxis(self.axis_x, Qt.AlignBottom)

        self.axis_left = QValueAxis()
        self.axis_left.setTitleText("ms")
        self.axis_left.setLabelFormat("%d")
        self.axis_left.setRange(0, 200)
        self.axis_left.setLabelsColor(QColor("#64748b"))
        self.axis_left.setTitleBrush(QBrush(QColor("#475569")))
        self.chart.addAxis(self.axis_left, Qt.AlignLeft)

        self.axis_right = QValueAxis()
        self.axis_right.setTitleText("% loss")
        self.axis_right.setLabelFormat("%d")
        self.axis_right.setRange(0, 100)
        self.axis_right.setLabelsColor(QColor("#64748b"))
        self.axis_right.setTitleBrush(QBrush(QColor("#475569")))
        self.chart.addAxis(self.axis_right, Qt.AlignRight)

        self.latency_series.attachAxis(self.axis_x)
        self.latency_series.attachAxis(self.axis_left)
        self.jitter_series.attachAxis(self.axis_x)
        self.jitter_series.attachAxis(self.axis_left)
        self.loss_series.attachAxis(self.axis_x)
        self.loss_series.attachAxis(self.axis_right)

        self.chart_view = QChartView(self.chart)
        self.chart_view.setMinimumHeight(220)
        self.chart_view.setRenderHint(QPainter.Antialiasing)
        layout.addWidget(self.chart_view)

        alerts_group = QGroupBox("Alerts")
        alerts_layout = QFormLayout()
        alerts_layout.setHorizontalSpacing(10)
        alerts_layout.setVerticalSpacing(6)
        self.alerts_check = QCheckBox("Enable alerts")
        self.alert_latency_spin = QSpinBox()
        self.alert_latency_spin.setRange(1, 10000)
        self.alert_latency_spin.setValue(150)
        self.alert_latency_spin.setSuffix(" ms")
        self.alert_loss_spin = QSpinBox()
        self.alert_loss_spin.setRange(0, 100)
        self.alert_loss_spin.setValue(5)
        self.alert_loss_spin.setSuffix(" %")
        self.alert_cooldown_spin = QSpinBox()
        self.alert_cooldown_spin.setRange(5, 3600)
        self.alert_cooldown_spin.setValue(60)
        self.alert_cooldown_spin.setSuffix(" s")
        self.alert_schedule_check = QCheckBox("Use schedule")
        self.alert_schedule_start = QTimeEdit()
        self.alert_schedule_start.setTime(QTime(8, 0))
        self.alert_schedule_end = QTimeEdit()
        self.alert_schedule_end.setTime(QTime(22, 0))
        alert_schedule_row = QHBoxLayout()
        alert_schedule_row.addWidget(self.alert_schedule_start)
        alert_schedule_row.addWidget(QLabel("to"))
        alert_schedule_row.addWidget(self.alert_schedule_end)
        alerts_layout.addRow(self.alerts_check)
        alerts_layout.addRow("Latency >", self.alert_latency_spin)
        alerts_layout.addRow("Loss >", self.alert_loss_spin)
        alerts_layout.addRow("Cooldown", self.alert_cooldown_spin)
        alerts_layout.addRow(self.alert_schedule_check)
        alerts_layout.addRow("Active hours", alert_schedule_row)
        alerts_group.setLayout(alerts_layout)
        alerts_group.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)
        alerts_group.setMaximumWidth(380)

        logging_group = QGroupBox("Logging")
        logging_layout = QFormLayout()
        logging_layout.setHorizontalSpacing(10)
        logging_layout.setVerticalSpacing(6)
        self.auto_log_check = QCheckBox("Auto log")
        self.log_format_combo = QComboBox()
        self.log_format_combo.addItems(["CSV", "JSONL"])
        self.log_path_input = QLineEdit()
        self.log_browse_button = QPushButton("Browse")
        self.log_browse_button.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.log_browse_button.setMinimumWidth(90)
        log_row = QHBoxLayout()
        log_row.addWidget(self.log_path_input)
        log_row.addWidget(self.log_browse_button)
        logging_layout.addRow(self.auto_log_check)
        logging_layout.addRow("Format:", self.log_format_combo)
        logging_layout.addRow("Log file:", log_row)
        logging_group.setLayout(logging_layout)
        logging_group.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)

        app_group = QGroupBox("App")
        app_layout = QFormLayout()
        app_layout.setHorizontalSpacing(10)
        app_layout.setVerticalSpacing(6)
        self.minimize_to_tray_check = QCheckBox("Minimize to tray on close")
        self.minimize_to_tray_check.setChecked(True)
        app_layout.addRow(self.minimize_to_tray_check)
        copyright_label = QLabel("Copyright (c) Mahesa")
        copyright_label.setProperty("role", "subtitle")
        app_layout.addRow(copyright_label)
        app_group.setLayout(app_layout)
        app_group.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)
        app_group.setMaximumWidth(320)

        settings_row = QGridLayout()
        settings_row.setHorizontalSpacing(12)
        settings_row.setVerticalSpacing(12)
        settings_row.addWidget(alerts_group, 0, 0)
        settings_row.addWidget(logging_group, 0, 1)
        settings_row.addWidget(app_group, 0, 2)
        settings_row.setColumnStretch(0, 1)
        settings_row.setColumnStretch(1, 2)
        settings_row.setColumnStretch(2, 1)
        settings_widget = QWidget()
        settings_widget.setLayout(settings_row)
        settings_widget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        settings_widget.setMinimumHeight(settings_widget.sizeHint().height())
        layout.addWidget(settings_widget)

        history_group = QGroupBox("History Summary")
        history_layout = QVBoxLayout()
        history_layout.setSpacing(6)
        history_layout.setContentsMargins(8, 8, 8, 10)
        self.history_24h_label = QLabel("-")
        self.history_7d_label = QLabel("-")
        self.load_history_button = QPushButton("Load Summary")
        self.load_history_button.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.load_history_button.setMinimumWidth(140)
        self.load_history_button.setMinimumHeight(32)
        history_row_24h = QHBoxLayout()
        history_row_24h.addWidget(QLabel("Last 24h:"))
        history_row_24h.addWidget(self.history_24h_label)
        history_row_24h.addStretch()
        history_layout.addLayout(history_row_24h)
        history_row_7d = QHBoxLayout()
        history_row_7d.addWidget(QLabel("Last 7d:"))
        history_row_7d.addWidget(self.history_7d_label)
        history_row_7d.addStretch()
        history_layout.addLayout(history_row_7d)
        history_button_row = QHBoxLayout()
        history_button_row.addWidget(self.load_history_button)
        history_button_row.addStretch()
        history_layout.addLayout(history_button_row)
        history_group.setLayout(history_layout)
        history_group.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        layout.addWidget(history_group, 0)

        self.monitor_log = QTextEdit()
        self.monitor_log.setReadOnly(True)
        layout.addWidget(self.monitor_log, 1)

        self.dashboard_tab.setLayout(layout)

        self.start_button.clicked.connect(self.start_monitor)
        self.stop_button.clicked.connect(self.stop_monitor)
        self.ping_button.clicked.connect(self.queue_ping)
        self.export_monitor_button.clicked.connect(self.export_monitor_history)
        self.log_browse_button.clicked.connect(self.select_log_file)
        self.load_history_button.clicked.connect(self.load_monitor_history_summary)

    def _build_speed(self):
        layout = QVBoxLayout()
        layout.setSpacing(12)
        layout.setContentsMargins(12, 12, 12, 12)

        header = QVBoxLayout()
        header.setSpacing(2)
        title = QLabel("Speed Test")
        title.setProperty("role", "title")
        subtitle = QLabel("Run a bandwidth test with speedtest or speedtest-cli.")
        subtitle.setProperty("role", "subtitle")
        header.addWidget(title)
        header.addWidget(subtitle)
        layout.addLayout(header)

        button_row = QHBoxLayout()
        self.run_speed_button = QPushButton("Run Speed Test")
        self.cancel_speed_button = QPushButton("Cancel")
        self.cancel_speed_button.setEnabled(False)
        button_row.addWidget(self.run_speed_button)
        button_row.addWidget(self.cancel_speed_button)
        button_row.addStretch()
        self.speed_status = QLabel("Idle")
        self.set_status_badge(self.speed_status, "idle", "Idle")
        self.speed_ping = QLabel("-")
        self.speed_download = QLabel("-")
        self.speed_upload = QLabel("-")
        self.speed_source = QLabel("-")
        self.speed_loss = QLabel("-")
        self.speed_isp = QLabel("-")
        self.speed_server = QLabel("-")
        self.speed_result = QLabel("-")
        self.speed_raw = QTextEdit()
        self.speed_raw.setReadOnly(True)
        self.show_raw_check = QCheckBox("Show raw JSON")
        self.copy_raw_button = QPushButton("Copy raw")
        self.copy_raw_button.setEnabled(False)
        self.raw_json = QTextEdit()
        self.raw_json.setReadOnly(True)
        self.raw_json.setVisible(False)

        layout.addLayout(button_row)

        results_layout = QFormLayout()
        results_layout.addRow("Status:", self.speed_status)
        results_layout.addRow("Ping (ms):", self.speed_ping)
        results_layout.addRow("Download (Mbps):", self.speed_download)
        results_layout.addRow("Upload (Mbps):", self.speed_upload)
        results_layout.addRow("Source:", self.speed_source)
        results_layout.addRow("Packet loss:", self.speed_loss)
        results_layout.addRow("ISP:", self.speed_isp)
        results_layout.addRow("Server:", self.speed_server)
        results_layout.addRow("Result URL:", self.speed_result)
        layout.addLayout(results_layout)

        layout.addWidget(self.speed_raw)
        raw_controls = QHBoxLayout()
        raw_controls.addWidget(self.show_raw_check)
        raw_controls.addWidget(self.copy_raw_button)
        raw_controls.addStretch()
        layout.addLayout(raw_controls)
        layout.addWidget(self.raw_json)
        self.speed_tab.setLayout(layout)

        self.run_speed_button.clicked.connect(self.run_speed_test)
        self.cancel_speed_button.clicked.connect(self.cancel_speed_test)
        self.show_raw_check.toggled.connect(self.toggle_raw_json)
        self.copy_raw_button.clicked.connect(self.copy_raw_json)

    def _build_devices(self):
        layout = QVBoxLayout()
        layout.setSpacing(12)
        layout.setContentsMargins(12, 12, 12, 12)

        header = QVBoxLayout()
        header.setSpacing(2)
        title = QLabel("Devices")
        title.setProperty("role", "title")
        subtitle = QLabel("Scan and track devices visible on your local network.")
        subtitle.setProperty("role", "subtitle")
        header.addWidget(title)
        header.addWidget(subtitle)
        layout.addLayout(header)

        form = QFormLayout()
        self.subnet_input = QLineEdit()
        default_subnet = get_default_subnet()
        if default_subnet:
            self.subnet_input.setText(default_subnet)
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(100, 2000)
        self.timeout_spin.setValue(250)
        self.timeout_spin.setSuffix(" ms")
        self.scan_profile_combo = QComboBox()
        self.scan_profile_combo.addItems(["Fast", "Normal", "Deep"])
        self.scan_profile_combo.setCurrentText("Normal")
        form.addRow("Subnet (CIDR):", self.subnet_input)
        form.addRow("Ping timeout:", self.timeout_spin)
        form.addRow("Scan profile:", self.scan_profile_combo)
        layout.addLayout(form)

        options_row = QHBoxLayout()
        self.resolve_names_check = QCheckBox("Resolve hostnames")
        self.resolve_names_check.setChecked(True)
        self.vendor_lookup_check = QCheckBox("Lookup vendor (OUI)")
        self.vendor_lookup_check.setChecked(True)
        options_row.addWidget(self.resolve_names_check)
        options_row.addWidget(self.vendor_lookup_check)
        options_row.addStretch()
        layout.addLayout(options_row)

        auto_row = QHBoxLayout()
        self.auto_scan_check = QCheckBox("Auto scan")
        self.auto_scan_interval_spin = QSpinBox()
        self.auto_scan_interval_spin.setRange(10, 3600)
        self.auto_scan_interval_spin.setValue(60)
        self.auto_scan_interval_spin.setSuffix(" s")
        self.new_device_alert_check = QCheckBox("Alert on new device")
        self.new_device_alert_check.setChecked(True)
        self.offline_device_alert_check = QCheckBox("Alert on device offline")
        self.device_sound_check = QCheckBox("Sound alert")
        self.device_sound_check.setChecked(True)
        self.offline_after_spin = QSpinBox()
        self.offline_after_spin.setRange(1, 120)
        self.offline_after_spin.setValue(5)
        self.offline_after_spin.setSuffix(" min")
        auto_row.addWidget(self.auto_scan_check)
        auto_row.addWidget(QLabel("Interval:"))
        auto_row.addWidget(self.auto_scan_interval_spin)
        auto_row.addWidget(self.new_device_alert_check)
        auto_row.addWidget(self.offline_device_alert_check)
        auto_row.addWidget(self.device_sound_check)
        auto_row.addWidget(QLabel("Offline after:"))
        auto_row.addWidget(self.offline_after_spin)
        auto_row.addStretch()
        layout.addLayout(auto_row)

        filter_row = QHBoxLayout()
        self.device_filter_input = QLineEdit()
        self.device_filter_input.setPlaceholderText(
            "Filter by IP, MAC, hostname, vendor, alias, notes..."
        )
        self.device_status_filter = QComboBox()
        self.device_status_filter.addItems(["All", "Online", "Offline"])
        filter_row.addWidget(QLabel("Filter:"))
        filter_row.addWidget(self.device_filter_input)
        filter_row.addWidget(self.device_status_filter)
        layout.addLayout(filter_row)

        export_row = QHBoxLayout()
        self.auto_export_check = QCheckBox("Auto export")
        self.auto_export_format = QComboBox()
        self.auto_export_format.addItems(["CSV", "JSONL"])
        self.auto_export_path_input = QLineEdit()
        self.auto_export_path_input.setPlaceholderText("Auto export path (optional)")
        self.auto_export_browse_button = QPushButton("Browse")
        export_row.addWidget(self.auto_export_check)
        export_row.addWidget(self.auto_export_format)
        export_row.addWidget(self.auto_export_path_input)
        export_row.addWidget(self.auto_export_browse_button)
        layout.addLayout(export_row)

        oui_row = QHBoxLayout()
        self.oui_status_label = QLabel()
        self.update_oui_status()
        self.download_oui_button = QPushButton("Download OUI")
        self.reload_oui_button = QPushButton("Reload OUI")
        oui_row.addWidget(self.oui_status_label)
        oui_row.addStretch()
        oui_row.addWidget(self.download_oui_button)
        oui_row.addWidget(self.reload_oui_button)
        layout.addLayout(oui_row)

        button_row = QHBoxLayout()
        self.scan_arp_button = QPushButton("Scan ARP Table")
        self.scan_network_button = QPushButton("Scan Network")
        self.scan_gateway_button = QPushButton("Scan Gateway")
        self.clear_devices_button = QPushButton("Clear History")
        self.export_devices_button = QPushButton("Export CSV")
        button_row.addWidget(self.scan_arp_button)
        button_row.addWidget(self.scan_network_button)
        button_row.addWidget(self.scan_gateway_button)
        button_row.addWidget(self.clear_devices_button)
        button_row.addWidget(self.export_devices_button)
        button_row.addStretch()

        layout.addLayout(button_row)

        status_row = QHBoxLayout()
        self.device_status_label = QLabel("Stopped")
        self.device_last_scan_label = QLabel("-")
        self.device_next_scan_label = QLabel("-")
        self.device_diff_label = QLabel("-")
        self.set_status_badge(self.device_status_label, "idle", "Stopped")
        status_row.addWidget(QLabel("Status:"))
        status_row.addWidget(self.device_status_label)
        status_row.addSpacing(20)
        status_row.addWidget(QLabel("Last scan:"))
        status_row.addWidget(self.device_last_scan_label)
        status_row.addSpacing(20)
        status_row.addWidget(QLabel("Next scan in:"))
        status_row.addWidget(self.device_next_scan_label)
        status_row.addSpacing(20)
        status_row.addWidget(QLabel("Diff:"))
        status_row.addWidget(self.device_diff_label)
        status_row.addStretch()
        layout.addLayout(status_row)

        self.devices_table = QTableWidget(0, 9)
        self.devices_table.setHorizontalHeaderLabels(
            [
                "IP",
                "MAC",
                "Type",
                "Hostname",
                "Alias",
                "Notes",
                "Vendor",
                "Status",
                "Last Seen",
            ]
        )
        self.devices_table.horizontalHeader().setStretchLastSection(True)
        self.devices_table.setAlternatingRowColors(True)
        layout.addWidget(self.devices_table)

        self.devices_tab.setLayout(layout)

        self.scan_arp_button.clicked.connect(self.scan_devices_arp)
        self.scan_network_button.clicked.connect(self.scan_devices_network)
        self.scan_gateway_button.clicked.connect(self.scan_gateway_only)
        self.clear_devices_button.clicked.connect(self.clear_device_history)
        self.export_devices_button.clicked.connect(self.export_devices)
        self.download_oui_button.clicked.connect(self.download_oui)
        self.reload_oui_button.clicked.connect(self.reload_oui)
        self.auto_scan_check.toggled.connect(self.toggle_auto_scan)
        self.auto_scan_interval_spin.valueChanged.connect(self.update_auto_scan_interval)
        self.scan_profile_combo.currentTextChanged.connect(self.apply_scan_profile)
        self.device_filter_input.textChanged.connect(self.refresh_device_table)
        self.device_status_filter.currentTextChanged.connect(self.refresh_device_table)
        self.auto_export_browse_button.clicked.connect(self.select_device_export_path)
        self.devices_table.itemChanged.connect(self.on_device_item_changed)

    def _build_wifi(self):
        layout = QVBoxLayout()
        layout.setSpacing(6)
        layout.setContentsMargins(6, 6, 6, 6)
        header = QVBoxLayout()
        header.setSpacing(2)
        title = QLabel("Wi-Fi")
        title.setProperty("role", "title")
        subtitle = QLabel("Current wireless interface details.")
        subtitle.setProperty("role", "subtitle")
        header.addWidget(title)
        header.addWidget(subtitle)
        layout.addLayout(header)
        self.refresh_wifi_button = QPushButton("Refresh Wi-Fi Details")
        self.wifi_status_label = QLabel("Idle")
        self.set_status_badge(self.wifi_status_label, "idle", "Idle")
        header_row = QHBoxLayout()
        header_row.addWidget(self.refresh_wifi_button)
        header_row.addWidget(self.wifi_status_label)
        header_row.addStretch()
        layout.addLayout(header_row)

        self.wifi_labels: dict[str, QLabel] = {}
        form = QFormLayout()
        form.setHorizontalSpacing(12)
        form.setVerticalSpacing(4)
        form.setContentsMargins(0, 0, 0, 0)
        for label in [
            "Name",
            "State",
            "SSID",
            "BSSID",
            "Signal",
            "Radio type",
            "Channel",
            "Receive rate (Mbps)",
            "Transmit rate (Mbps)",
            "Authentication",
        ]:
            value_label = QLabel("-")
            self.wifi_labels[label] = value_label
            form.addRow(f"{label}:", value_label)

        form_wrapper = QWidget()
        form_wrapper.setLayout(form)
        form_wrapper.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        layout.addWidget(form_wrapper)
        layout.addStretch()
        self.wifi_tab.setLayout(layout)

        self.refresh_wifi_button.clicked.connect(self.refresh_wifi_details)

    def _build_diagnostics(self):
        layout = QVBoxLayout()
        layout.setSpacing(12)
        layout.setContentsMargins(12, 12, 12, 12)

        header = QVBoxLayout()
        header.setSpacing(2)
        title = QLabel("Diagnostics")
        title.setProperty("role", "title")
        subtitle = QLabel("Quick network checks and system commands.")
        subtitle.setProperty("role", "subtitle")
        header.addWidget(title)
        header.addWidget(subtitle)
        layout.addLayout(header)

        form = QFormLayout()
        self.diag_target_input = QLineEdit("8.8.8.8")
        form.addRow("Target:", self.diag_target_input)
        layout.addLayout(form)

        button_row = QHBoxLayout()
        self.diag_quick_button = QPushButton("Quick Diagnostics")
        self.diag_ping_gateway_button = QPushButton("Ping Gateway")
        self.diag_ping_dns_button = QPushButton("Ping 8.8.8.8")
        self.diag_traceroute_button = QPushButton("Traceroute")
        self.diag_flush_dns_button = QPushButton("Flush DNS")
        self.diag_renew_dhcp_button = QPushButton("Renew DHCP")
        self.diag_clear_button = QPushButton("Clear Output")
        button_row.addWidget(self.diag_quick_button)
        button_row.addWidget(self.diag_ping_gateway_button)
        button_row.addWidget(self.diag_ping_dns_button)
        button_row.addWidget(self.diag_traceroute_button)
        button_row.addWidget(self.diag_flush_dns_button)
        button_row.addWidget(self.diag_renew_dhcp_button)
        button_row.addWidget(self.diag_clear_button)
        button_row.addStretch()
        layout.addLayout(button_row)

        self.diag_status_label = QLabel("Idle")
        self.set_status_badge(self.diag_status_label, "idle", "Idle")
        layout.addWidget(self.diag_status_label)

        self.diag_output = QTextEdit()
        self.diag_output.setReadOnly(True)
        layout.addWidget(self.diag_output)

        self.diagnostics_tab.setLayout(layout)

        self.diag_quick_button.clicked.connect(self.run_quick_diagnostics)
        self.diag_ping_gateway_button.clicked.connect(self.run_ping_gateway_diag)
        self.diag_ping_dns_button.clicked.connect(self.run_ping_dns_diag)
        self.diag_traceroute_button.clicked.connect(self.run_traceroute_diag)
        self.diag_flush_dns_button.clicked.connect(self.run_flush_dns_diag)
        self.diag_renew_dhcp_button.clicked.connect(self.run_renew_dhcp_diag)
        self.diag_clear_button.clicked.connect(self.diag_output.clear)

    def _setup_tray(self):
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        self.tray = QSystemTrayIcon(self)
        self.tray.setIcon(self.style().standardIcon(QStyle.SP_ComputerIcon))
        menu = QMenu()
        self.tray_show_action = QAction("Show")
        self.tray_quit_action = QAction("Quit")
        menu.addAction(self.tray_show_action)
        menu.addAction(self.tray_quit_action)
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(self.on_tray_activated)
        self.tray_show_action.triggered.connect(self.show_normal)
        self.tray_quit_action.triggered.connect(self.exit_app)
        self.tray.show()

    def _apply_theme(self):
        self.setFont(QFont("Segoe UI Variable", 10))
        self.apply_theme(self.dark_mode_enabled)

    def apply_theme(self, dark: bool):
        if dark:
            self.setStyleSheet(
                """
                QMainWindow { background-color: #0b1120; }
                QTabWidget::pane {
                    border: 1px solid #1f2937;
                    border-radius: 12px;
                    background: #0f172a;
                }
                QTabBar::tab {
                    background: #111827;
                    color: #cbd5e1;
                    padding: 8px 16px;
                    border: 1px solid #1f2937;
                    border-bottom: none;
                    border-top-left-radius: 10px;
                    border-top-right-radius: 10px;
                    margin-right: 6px;
                }
                QTabBar::tab:selected {
                    background: #0f172a;
                    color: #e2e8f0;
                    border: 1px solid #1f2937;
                    border-bottom-color: #0f172a;
                }
                QLabel[role="title"] {
                    font-size: 16px;
                    font-weight: 600;
                    color: #e2e8f0;
                }
                QLabel[role="subtitle"] { color: #94a3b8; }
                QLabel[role="kpi"] {
                    font-weight: 600;
                    background: #0b1220;
                    border: 1px solid #1f2937;
                    border-radius: 8px;
                    padding: 2px 8px;
                    color: #e2e8f0;
                }
                QLabel[role="score"] {
                    font-weight: 700;
                    background: #0f2f3a;
                    border: 1px solid #155e75;
                    border-radius: 10px;
                    padding: 2px 10px;
                    color: #e2e8f0;
                }
                QLabel[badge="true"] {
                    padding: 2px 8px;
                    border-radius: 999px;
                    font-weight: 600;
                }
                QLabel[badge="true"][status="running"] {
                    background: #0f2f3a;
                    color: #7dd3fc;
                    border: 1px solid #155e75;
                }
                QLabel[badge="true"][status="idle"] {
                    background: #0b1220;
                    color: #94a3b8;
                    border: 1px solid #1f2937;
                }
                QLabel[badge="true"][status="ok"] {
                    background: #0b2f2a;
                    color: #86efac;
                    border: 1px solid #14532d;
                }
                QLabel[badge="true"][status="error"] {
                    background: #3f1d1d;
                    color: #fecaca;
                    border: 1px solid #7f1d1d;
                }
                QLabel[badge="true"][status="warn"] {
                    background: #3b2f1a;
                    color: #fde68a;
                    border: 1px solid #92400e;
                }
                QPushButton {
                    background: #0f766e;
                    color: #e2e8f0;
                    border-radius: 10px;
                    padding: 7px 14px;
                }
                QPushButton:hover { background: #0d9488; }
                QPushButton:pressed { background: #0f766e; }
                QPushButton:disabled { background: #1f2937; color: #64748b; }
                QLineEdit, QSpinBox, QTextEdit, QTableWidget, QComboBox, QTimeEdit {
                    background: #0b1220;
                    border: 1px solid #1f2937;
                    border-radius: 8px;
                    padding: 6px 8px;
                    color: #e2e8f0;
                }
                QLineEdit:focus, QSpinBox:focus, QTextEdit:focus, QTableWidget:focus, QComboBox:focus, QTimeEdit:focus {
                    border: 1px solid #0f766e;
                }
                QComboBox::drop-down {
                    border: none;
                    width: 22px;
                }
                QComboBox::down-arrow {
                    width: 10px;
                    height: 10px;
                    image: none;
                }
                QTableWidget::item { padding: 4px; }
                QTableWidget::item:alternate { background: #0f172a; }
                QTableWidget::item:selected { background: #1d4ed8; color: #e2e8f0; }
                QHeaderView::section {
                    background: #0f172a;
                    color: #cbd5e1;
                    padding: 8px;
                    border: 1px solid #1f2937;
                }
                QGroupBox {
                    border: 1px solid #1f2937;
                    border-radius: 12px;
                    margin-top: 14px;
                    padding: 8px;
                    background: #111827;
                }
                QGroupBox::title {
                    subcontrol-origin: margin;
                    left: 12px;
                    padding: 0 6px;
                    color: #e2e8f0;
                    font-weight: 600;
                }
                QLabel { color: #e2e8f0; }
                QCheckBox { color: #e2e8f0; spacing: 6px; }
                """
            )
        else:
            self.setStyleSheet(
                """
                QMainWindow { background-color: #f7f8fb; }
                QTabWidget::pane {
                    border: 1px solid #e2e8f0;
                    border-radius: 12px;
                    background: #f8fafc;
                }
                QTabBar::tab {
                    background: #eef2f7;
                    color: #334155;
                    padding: 8px 16px;
                    border: 1px solid #e2e8f0;
                    border-bottom: none;
                    border-top-left-radius: 10px;
                    border-top-right-radius: 10px;
                    margin-right: 6px;
                }
                QTabBar::tab:selected {
                    background: #ffffff;
                    color: #0f172a;
                    border: 1px solid #e2e8f0;
                    border-bottom-color: #ffffff;
                }
                QLabel[role="title"] {
                    font-size: 16px;
                    font-weight: 600;
                    color: #0f172a;
                }
                QLabel[role="subtitle"] { color: #64748b; }
                QLabel[role="kpi"] {
                    font-weight: 600;
                    background: #f1f5f9;
                    border: 1px solid #e2e8f0;
                    border-radius: 8px;
                    padding: 2px 8px;
                }
                QLabel[role="score"] {
                    font-weight: 700;
                    background: #ecfeff;
                    border: 1px solid #a5f3fc;
                    border-radius: 10px;
                    padding: 2px 10px;
                }
                QLabel[badge="true"] {
                    padding: 2px 8px;
                    border-radius: 999px;
                    font-weight: 600;
                }
                QLabel[badge="true"][status="running"] {
                    background: #ecfeff;
                    color: #155e75;
                    border: 1px solid #a5f3fc;
                }
                QLabel[badge="true"][status="idle"] {
                    background: #f1f5f9;
                    color: #475569;
                    border: 1px solid #e2e8f0;
                }
                QLabel[badge="true"][status="ok"] {
                    background: #ecfdf3;
                    color: #065f46;
                    border: 1px solid #a7f3d0;
                }
                QLabel[badge="true"][status="error"] {
                    background: #fee2e2;
                    color: #b91c1c;
                    border: 1px solid #fecaca;
                }
                QLabel[badge="true"][status="warn"] {
                    background: #fef3c7;
                    color: #92400e;
                    border: 1px solid #fde68a;
                }
                QPushButton {
                    background: #0f766e;
                    color: #ffffff;
                    border-radius: 10px;
                    padding: 7px 14px;
                }
                QPushButton:hover { background: #0d9488; }
                QPushButton:pressed { background: #0f766e; }
                QPushButton:disabled { background: #cbd5e1; color: #94a3b8; }
                QLineEdit, QSpinBox, QTextEdit, QTableWidget, QComboBox, QTimeEdit {
                    background: #ffffff;
                    border: 1px solid #e2e8f0;
                    border-radius: 8px;
                    padding: 6px 8px;
                    color: #0f172a;
                }
                QLineEdit:focus, QSpinBox:focus, QTextEdit:focus, QTableWidget:focus, QComboBox:focus, QTimeEdit:focus {
                    border: 1px solid #0f766e;
                }
                QComboBox::drop-down {
                    border: none;
                    width: 22px;
                }
                QComboBox::down-arrow {
                    width: 10px;
                    height: 10px;
                    image: none;
                }
                QTableWidget::item { padding: 4px; }
                QTableWidget::item:alternate { background: #f8fafc; }
                QTableWidget::item:selected { background: #dbeafe; color: #0f172a; }
                QHeaderView::section {
                    background: #f8fafc;
                    color: #334155;
                    padding: 8px;
                    border: 1px solid #e2e8f0;
                }
                QGroupBox {
                    border: 1px solid #e2e8f0;
                    border-radius: 12px;
                    margin-top: 14px;
                    padding: 8px;
                    background: #ffffff;
                }
                QGroupBox::title {
                    subcontrol-origin: margin;
                    left: 12px;
                    padding: 0 6px;
                    color: #0f172a;
                    font-weight: 600;
                }
                QLabel { color: #0f172a; }
                QCheckBox { color: #0f172a; spacing: 6px; }
                """
            )
        self.apply_chart_theme(dark)

    def apply_chart_theme(self, dark: bool):
        if not hasattr(self, "chart"):
            return
        if dark:
            self.chart.setBackgroundBrush(QBrush(QColor("#0f172a")))
            self.chart.setTitleBrush(QBrush(QColor("#e2e8f0")))
            self.chart.legend().setLabelColor(QColor("#cbd5e1"))
            self.latency_series.setPen(QPen(QColor("#60a5fa"), 2))
            self.jitter_series.setPen(QPen(QColor("#fbbf24"), 2))
            self.loss_series.setPen(QPen(QColor("#f87171"), 2))
            grid = QColor("#1f2937")
            label = QColor("#cbd5e1")
            title = QColor("#e2e8f0")
        else:
            self.chart.setBackgroundBrush(QBrush(QColor("#ffffff")))
            self.chart.setTitleBrush(QBrush(QColor("#0f172a")))
            self.chart.legend().setLabelColor(QColor("#475569"))
            self.latency_series.setPen(QPen(QColor("#2563eb"), 2))
            self.jitter_series.setPen(QPen(QColor("#f59e0b"), 2))
            self.loss_series.setPen(QPen(QColor("#ef4444"), 2))
            grid = QColor("#e2e8f0")
            label = QColor("#64748b")
            title = QColor("#475569")

        for axis in (self.axis_x, self.axis_left, self.axis_right):
            axis.setGridLineColor(grid)
            axis.setLabelsColor(label)
            axis.setTitleBrush(QBrush(title))

    def toggle_dark_mode(self, enabled: bool):
        self.dark_mode_enabled = enabled
        self.apply_theme(enabled)
        self.refresh_device_table()

    def animate_tab_transition(self, index: int):
        widget = self.tabs.widget(index)
        if not widget:
            return
        effect = QGraphicsOpacityEffect(widget)
        widget.setGraphicsEffect(effect)
        animation = QPropertyAnimation(effect, b"opacity", widget)
        animation.setDuration(220)
        animation.setStartValue(0.0)
        animation.setEndValue(1.0)
        animation.setEasingCurve(QEasingCurve.OutCubic)

        def cleanup():
            widget.setGraphicsEffect(None)
            if animation in self.active_animations:
                self.active_animations.remove(animation)

        animation.finished.connect(cleanup)
        self.active_animations.append(animation)
        animation.start()

    def on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.Trigger:
            self.show_normal()

    def show_normal(self):
        self.show()
        self.raise_()
        self.activateWindow()

    def exit_app(self):
        self.minimize_to_tray_check.setChecked(False)
        self.close()

    def closeEvent(self, event):
        if self.minimize_to_tray_check.isChecked() and hasattr(self, "tray"):
            event.ignore()
            self.hide()
            if not self.tray_notified:
                self.tray.showMessage(
                    "Wi-Fi Toolkit",
                    "App is still running in the tray.",
                    QSystemTrayIcon.Information,
                    3000,
                )
                self.tray_notified = True
            return
        event.accept()

    def start_monitor(self):
        if self.monitor_running:
            return
        self.monitor_running = True
        self.set_status_badge(self.status_label, "running", "Running")
        self.timer.start(self.interval_spin.value() * 1000)
        self.monitor_countdown_timer.start(1000)
        self.queue_ping()

    def stop_monitor(self):
        if not self.monitor_running:
            return
        self.monitor_running = False
        self.set_status_badge(self.status_label, "idle", "Stopped")
        self.timer.stop()
        self.monitor_countdown_timer.stop()
        self.monitor_next_run_at = None
        self.next_ping_label.setText("-")

    def queue_ping(self):
        if self.ping_in_flight:
            return
        base_targets = parse_target_list(self.host_input.text())
        include_gateway = self.include_gateway_check.isChecked()
        include_dns = self.include_dns_check.isChecked()
        if not base_targets and not include_gateway and not include_dns:
            self.append_monitor_log("No targets configured.")
            return

        self.ping_in_flight = True
        self.set_status_badge(self.status_label, "running", "Running")
        self.append_monitor_log("Pinging targets...")
        self.monitor_next_run_at = time.monotonic() + self.interval_spin.value()
        self.update_monitor_countdown()

        self.start_worker(
            lambda: run_monitor_ping(base_targets, include_gateway, include_dns, 1000),
            self.on_ping_result,
            self.on_ping_error,
        )

    def update_monitor_countdown(self):
        if not self.monitor_running or self.monitor_next_run_at is None:
            self.next_ping_label.setText("-")
            return
        remaining = int(self.monitor_next_run_at - time.monotonic())
        if remaining < 0:
            remaining = 0
        self.next_ping_label.setText(f"{remaining} s")
        if not self.ping_in_flight:
            self.set_status_badge(self.status_label, "idle", "Stopped")

    def set_status_badge(self, label: QLabel, status: str, text: str):
        label.setText(text)
        label.setProperty("badge", True)
        label.setProperty("status", status)
        label.style().unpolish(label)
        label.style().polish(label)

    def on_ping_result(self, result: dict | list[dict]):
        self.ping_in_flight = False
        if isinstance(result, dict) and "results" in result:
            results = result.get("results") or []
            self.monitor_targets_current = result.get("targets", [])
            self.monitor_primary_target = (
                self.monitor_targets_current[0] if self.monitor_targets_current else None
            )
            self.monitor_gateway_target = result.get("gateway")
            self.monitor_dns_target = result.get("dns")
            if self.monitor_targets_current:
                self.append_monitor_log(f"Pinging: {', '.join(self.monitor_targets_current)}")
        else:
            results = result if isinstance(result, list) else [result]
        primary_host = self.monitor_primary_target or (results[0].get("host") if results else None)
        primary_result = None
        for item in results:
            if item.get("host") == primary_host:
                primary_result = item
                break
        if not primary_result and results:
            primary_result = results[0]

        avg_ms = primary_result.get("avg_ms") if primary_result else None
        loss_percent = primary_result.get("loss_percent") if primary_result else None
        jitter_ms = None
        if avg_ms is not None and self.last_latency_ms is not None:
            jitter_ms = abs(avg_ms - self.last_latency_ms)
        if avg_ms is not None:
            self.last_latency_ms = avg_ms
        now = QDateTime.currentDateTime().toString("yyyy-MM-dd HH:mm:ss")

        if avg_ms is not None:
            self.latency_label.setText(f"{avg_ms} ms")
        else:
            self.latency_label.setText("-")
        if jitter_ms is not None:
            self.jitter_label.setText(f"{jitter_ms} ms")
        else:
            self.jitter_label.setText("-")
        if loss_percent is not None:
            self.loss_label.setText(f"{loss_percent}%")
        else:
            self.loss_label.setText("-")

        self.updated_label.setText(now)

        for item in results:
            is_primary = item is primary_result
            entry = {
                "timestamp": now,
                "host": item.get("host"),
                "avg_ms": item.get("avg_ms"),
                "jitter_ms": jitter_ms if is_primary else None,
                "loss_percent": item.get("loss_percent"),
            }
            self.monitor_history.append(entry)
            self.append_monitor_log_file(entry)

        avg_text = f"{avg_ms} ms" if avg_ms is not None else "-"
        jitter_text = f"{jitter_ms} ms" if jitter_ms is not None else "-"
        loss_text = f"{loss_percent}%" if loss_percent is not None else "-"
        self.append_monitor_log(
            f"{now} | {primary_host} | avg {avg_text} | jitter {jitter_text} | loss {loss_text}"
        )
        for item in results:
            if item is primary_result:
                continue
            avg_item = item.get("avg_ms")
            loss_item = item.get("loss_percent")
            avg_item_text = f"{avg_item} ms" if avg_item is not None else "-"
            loss_item_text = f"{loss_item}%" if loss_item is not None else "-"
            self.append_monitor_log(
                f"{now} | {item.get('host')} | avg {avg_item_text} | loss {loss_item_text}"
            )
        self.update_chart(avg_ms, jitter_ms, loss_percent)
        self.maybe_send_alert(avg_ms, loss_percent)
        self.update_health_score(primary_host)
        self.update_root_cause_hint(results)
        if self.monitor_running:
            self.set_status_badge(self.status_label, "idle", "Stopped")

    def on_ping_error(self, message: str):
        self.ping_in_flight = False
        self.append_monitor_log(f"Ping error: {message}")
        if self.monitor_running:
            self.set_status_badge(self.status_label, "idle", "Stopped")

    def export_monitor_history(self):
        if not self.monitor_history:
            self.append_monitor_log("No monitor history to export.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Monitor History",
            "monitor_history.csv",
            "CSV Files (*.csv)",
        )
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=["timestamp", "host", "avg_ms", "jitter_ms", "loss_percent"],
            )
            writer.writeheader()
            writer.writerows(self.monitor_history)
        self.append_monitor_log(f"Exported monitor history to {path}")

    def get_default_log_path(self) -> Path:
        log_dir = get_app_dir() / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        suffix = "csv" if self.log_format_combo.currentText() == "CSV" else "jsonl"
        filename = f"monitor_{datetime.now().strftime('%Y%m%d')}.{suffix}"
        return log_dir / filename

    def select_log_file(self):
        suffix = "csv" if self.log_format_combo.currentText() == "CSV" else "jsonl"
        filename = f"monitor_{datetime.now().strftime('%Y%m%d')}.{suffix}"
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Select Log File",
            filename,
            "CSV Files (*.csv);;JSON Lines (*.jsonl)",
        )
        if path:
            self.log_path_input.setText(path)

    def append_monitor_log_file(self, entry: dict):
        if not self.auto_log_check.isChecked():
            return

        path_text = self.log_path_input.text().strip()
        path = Path(path_text) if path_text else self.get_default_log_path()
        if not path_text:
            self.log_path_input.setText(str(path))

        path.parent.mkdir(parents=True, exist_ok=True)
        if self.log_format_combo.currentText() == "CSV":
            file_exists = path.exists()
            with open(path, "a", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=["timestamp", "host", "avg_ms", "jitter_ms", "loss_percent"],
                )
                if not file_exists:
                    writer.writeheader()
                writer.writerow(entry)
        else:
            with open(path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, ensure_ascii=True) + "\n")

    def update_chart(
        self,
        avg_ms: int | None,
        jitter_ms: int | None,
        loss_percent: int | None,
    ):
        self.sample_index += 1
        x_value = self.sample_index
        if avg_ms is None:
            avg_ms = 0
        if jitter_ms is None:
            jitter_ms = 0
        if loss_percent is None:
            loss_percent = 0

        self.latency_series.append(x_value, avg_ms)
        self.jitter_series.append(x_value, jitter_ms)
        self.loss_series.append(x_value, loss_percent)

        for series in (self.latency_series, self.jitter_series, self.loss_series):
            if series.count() > self.max_points:
                series.removePoints(0, series.count() - self.max_points)

        min_x = max(0, x_value - self.max_points + 1)
        self.axis_x.setRange(min_x, x_value)
        max_ms = max(avg_ms, jitter_ms, 50)
        self.axis_left.setRange(0, max(50, max_ms + 20))

    def is_alert_schedule_active(self) -> bool:
        if not self.alert_schedule_check.isChecked():
            return True
        start = self.alert_schedule_start.time()
        end = self.alert_schedule_end.time()
        now = QTime.currentTime()
        if start <= end:
            return start <= now <= end
        return now >= start or now <= end

    def update_health_score(self, host: str | None):
        if not host:
            self.health_score_label.setText("-")
            return
        recent = [entry for entry in self.monitor_history if entry.get("host") == host][-30:]
        if not recent:
            self.health_score_label.setText("-")
            return
        avg_lat = [entry.get("avg_ms") for entry in recent if entry.get("avg_ms") is not None]
        avg_loss = [
            entry.get("loss_percent")
            for entry in recent
            if entry.get("loss_percent") is not None
        ]
        avg_jitter = [
            entry.get("jitter_ms") for entry in recent if entry.get("jitter_ms") is not None
        ]
        latency = sum(avg_lat) / len(avg_lat) if avg_lat else None
        loss = sum(avg_loss) / len(avg_loss) if avg_loss else None
        jitter = sum(avg_jitter) / len(avg_jitter) if avg_jitter else None

        score = 100.0
        if latency is not None:
            score -= max(0.0, latency - 50.0) * 0.4
        if jitter is not None:
            score -= max(0.0, jitter - 10.0) * 0.5
        if loss is not None:
            score -= loss * 2.0
        score = max(0.0, min(100.0, score))
        self.health_score_label.setText(f"{score:.0f}/100")

    def update_root_cause_hint(self, results: list[dict]):
        def is_failure(item: dict) -> bool:
            loss = item.get("loss_percent")
            avg = item.get("avg_ms")
            return loss == 100 or avg is None

        gateway_result = None
        dns_result = None
        internet_fail = False

        for item in results:
            host = item.get("host")
            if self.monitor_gateway_target and host == self.monitor_gateway_target:
                gateway_result = item
            if self.monitor_dns_target and host == self.monitor_dns_target:
                dns_result = item
            if host and host not in {self.monitor_gateway_target, self.monitor_dns_target}:
                internet_fail = internet_fail or is_failure(item)

        if gateway_result and is_failure(gateway_result):
            self.root_cause_label.setText("Local network / gateway unreachable")
            return
        if dns_result and is_failure(dns_result):
            self.root_cause_label.setText("DNS or ISP issue")
            return
        if internet_fail:
            self.root_cause_label.setText("WAN/ISP issue")
            return
        self.root_cause_label.setText("Healthy")

    def parse_log_timestamp(self, value: str) -> datetime | None:
        try:
            return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
        except (TypeError, ValueError):
            return None

    def safe_float(self, value: str | float | int | None) -> float | None:
        if value is None:
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    def summarize_history_entries(self, entries: list[dict]) -> str:
        if not entries:
            return "No data"
        avg_lat = [entry.get("avg_ms") for entry in entries if entry.get("avg_ms") is not None]
        avg_loss = [
            entry.get("loss_percent")
            for entry in entries
            if entry.get("loss_percent") is not None
        ]
        avg_jitter = [
            entry.get("jitter_ms") for entry in entries if entry.get("jitter_ms") is not None
        ]
        latency = sum(avg_lat) / len(avg_lat) if avg_lat else None
        loss = sum(avg_loss) / len(avg_loss) if avg_loss else None
        jitter = sum(avg_jitter) / len(avg_jitter) if avg_jitter else None
        parts = []
        if latency is not None:
            parts.append(f"avg latency {latency:.0f} ms")
        if jitter is not None:
            parts.append(f"avg jitter {jitter:.0f} ms")
        if loss is not None:
            parts.append(f"avg loss {loss:.1f}%")
        parts.append(f"samples {len(entries)}")
        return ", ".join(parts)

    def load_monitor_history_summary(self):
        now = datetime.now()
        cutoff_24h = now.timestamp() - 24 * 3600
        cutoff_7d = now.timestamp() - 7 * 24 * 3600

        entries: list[dict] = []
        path_text = self.log_path_input.text().strip()
        log_path = Path(path_text) if path_text else None
        if not log_path and self.auto_log_check.isChecked():
            log_path = self.get_default_log_path()
        if log_path and log_path.exists():
            fmt = self.log_format_combo.currentText()
            if fmt == "CSV":
                with open(log_path, "r", encoding="utf-8", newline="") as handle:
                    reader = csv.DictReader(handle)
                    for row in reader:
                        ts = self.parse_log_timestamp(row.get("timestamp"))
                        if not ts:
                            continue
                        entries.append(
                            {
                                "timestamp": ts,
                                "avg_ms": self.safe_float(row.get("avg_ms")),
                                "jitter_ms": self.safe_float(row.get("jitter_ms")),
                                "loss_percent": self.safe_float(row.get("loss_percent")),
                            }
                        )
            else:
                with open(log_path, "r", encoding="utf-8") as handle:
                    for line in handle:
                        if not line.strip():
                            continue
                        try:
                            payload = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        ts = self.parse_log_timestamp(payload.get("timestamp"))
                        if not ts:
                            continue
                        entries.append(
                            {
                                "timestamp": ts,
                                "avg_ms": payload.get("avg_ms"),
                                "jitter_ms": payload.get("jitter_ms"),
                                "loss_percent": payload.get("loss_percent"),
                            }
                        )
        else:
            for entry in self.monitor_history:
                ts = self.parse_log_timestamp(entry.get("timestamp"))
                if not ts:
                    continue
                entries.append(
                    {
                        "timestamp": ts,
                        "avg_ms": entry.get("avg_ms"),
                        "jitter_ms": entry.get("jitter_ms"),
                        "loss_percent": entry.get("loss_percent"),
                    }
                )

        entries_24h = [entry for entry in entries if entry["timestamp"].timestamp() >= cutoff_24h]
        entries_7d = [entry for entry in entries if entry["timestamp"].timestamp() >= cutoff_7d]

        self.history_24h_label.setText(self.summarize_history_entries(entries_24h))
        self.history_7d_label.setText(self.summarize_history_entries(entries_7d))

    def load_device_notes(self) -> dict[str, dict]:
        if not self.device_notes_path.exists():
            return {}
        try:
            with open(self.device_notes_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return {}
        if isinstance(payload, dict):
            return payload
        return {}

    def save_device_notes(self):
        self.device_notes_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.device_notes_path, "w", encoding="utf-8") as handle:
            json.dump(self.device_notes, handle, ensure_ascii=True, indent=2)

    def maybe_send_alert(self, avg_ms: int | None, loss_percent: int | None):
        if not self.alerts_check.isChecked():
            return
        if avg_ms is None and loss_percent is None:
            return
        if not self.is_alert_schedule_active():
            return

        latency_threshold = self.alert_latency_spin.value()
        loss_threshold = self.alert_loss_spin.value()
        should_alert = False
        reasons = []

        if avg_ms is not None and avg_ms > latency_threshold:
            should_alert = True
            reasons.append(f"latency {avg_ms} ms")
        if loss_percent is not None and loss_percent > loss_threshold:
            should_alert = True
            reasons.append(f"loss {loss_percent}%")

        if not should_alert:
            return

        now = time.monotonic()
        if now - self.last_alert_time < self.alert_cooldown_spin.value():
            return

        if not hasattr(self, "tray"):
            return

        self.last_alert_time = now
        detail = ", ".join(reasons)
        self.tray.showMessage("Wi-Fi Toolkit Alert", detail, QSystemTrayIcon.Information, 5000)
        self.append_monitor_log(f"ALERT: {detail}")

    def run_speed_test(self):
        if self.speedtest_in_flight:
            return
        self.speedtest_in_flight = True
        self.speedtest_cancel_event = threading.Event()
        self.set_status_badge(self.speed_status, "running", "Running")
        self.speed_raw.clear()
        self.run_speed_button.setEnabled(False)
        self.cancel_speed_button.setEnabled(True)

        self.start_worker(
            lambda: run_speedtest(self.speedtest_cancel_event),
            self.on_speed_result,
            self.on_speed_error,
        )

    def on_speed_result(self, result: dict):
        self.speedtest_in_flight = False
        self.run_speed_button.setEnabled(True)
        self.cancel_speed_button.setEnabled(False)
        self.set_status_badge(self.speed_status, "ok", "Done")
        self.speed_ping.setText(
            f"{result.get('ping_ms'):.2f}" if result.get("ping_ms") else "-"
        )
        self.speed_download.setText(f"{result.get('download_mbps'):.2f}")
        self.speed_upload.setText(f"{result.get('upload_mbps'):.2f}")
        self.speed_source.setText(result.get("source", "-"))
        packet_loss = result.get("packet_loss")
        if packet_loss is None:
            self.speed_loss.setText("-")
        else:
            try:
                self.speed_loss.setText(f"{float(packet_loss):.2f}%")
            except (TypeError, ValueError):
                self.speed_loss.setText(str(packet_loss))
        self.speed_isp.setText(result.get("isp") or "-")
        server_name = result.get("server_name")
        server_location = result.get("server_location")
        if server_name and server_location:
            server_text = f"{server_name} ({server_location})"
        elif server_name:
            server_text = server_name
        elif server_location:
            server_text = server_location
        else:
            server_text = "-"
        self.speed_server.setText(server_text)
        self.speed_result.setText(result.get("result_url") or "-")
        self.speed_raw.setPlainText(format_speedtest_text(result))
        self.speed_raw_json_text = result.get("raw", "")
        self.raw_json.setPlainText(self.speed_raw_json_text)
        self.copy_raw_button.setEnabled(bool(self.speed_raw_json_text))
        self.toggle_raw_json(self.show_raw_check.isChecked())

    def on_speed_error(self, message: str):
        self.speedtest_in_flight = False
        self.run_speed_button.setEnabled(True)
        self.cancel_speed_button.setEnabled(False)
        status = "Error"
        lowered = message.lower()
        if "cancelled" in lowered:
            status = "Cancelled"
        elif "timed out" in lowered:
            status = "Timed out"
        badge_status = "error" if status == "Error" else "warn"
        self.set_status_badge(self.speed_status, badge_status, status)
        self.speed_raw.setPlainText(message)
        self.speed_loss.setText("-")
        self.speed_isp.setText("-")
        self.speed_server.setText("-")
        self.speed_result.setText("-")
        self.speed_raw_json_text = ""
        self.raw_json.clear()
        self.copy_raw_button.setEnabled(False)

    def toggle_raw_json(self, show: bool):
        self.raw_json.setVisible(show)

    def copy_raw_json(self):
        if not self.speed_raw_json_text:
            return
        QApplication.clipboard().setText(self.speed_raw_json_text)

    def cancel_speed_test(self):
        if not self.speedtest_in_flight or not self.speedtest_cancel_event:
            return
        self.set_status_badge(self.speed_status, "warn", "Cancelling")
        self.speedtest_cancel_event.set()

    def refresh_wifi_details(self):
        self.set_status_badge(self.wifi_status_label, "running", "Refreshing")
        self.start_worker(get_wifi_details, self.on_wifi_result, self.on_wifi_error)

    def on_wifi_result(self, details: dict):
        self.set_status_badge(self.wifi_status_label, "ok", "Updated")
        for key, label in self.wifi_labels.items():
            label.setText(details.get(key, "-") or "-")

    def on_wifi_error(self, message: str):
        self.set_status_badge(self.wifi_status_label, "error", "Error")
        for label in self.wifi_labels.values():
            label.setText("-")
        self.append_monitor_log(f"Wi-Fi details error: {message}")

    def append_diag_output(self, text: str):
        timestamp = QDateTime.currentDateTime().toString("HH:mm:ss")
        self.diag_output.append(f"[{timestamp}] {text}")

    def run_diagnostic_commands(self, title: str, commands: list[list[str]]):
        self.set_status_badge(self.diag_status_label, "running", "Running")
        self.append_diag_output(f"Starting: {title}")

        def job():
            outputs = []
            for cmd in commands:
                outputs.append(run_command_capture(cmd, timeout_s=30))
            return outputs

        self.start_worker(
            job,
            lambda results: self.on_diag_result(title, results),
            self.on_diag_error,
        )

    def on_diag_result(self, title: str, results: list[dict]):
        self.set_status_badge(self.diag_status_label, "ok", "Done")
        for result in results:
            header = f"{title} -> {result.get('cmd')} (rc={result.get('returncode')})"
            self.append_diag_output(header)
            stdout = result.get("stdout") or ""
            stderr = result.get("stderr") or ""
            if stdout:
                self.append_diag_output(stdout)
            if stderr:
                self.append_diag_output(stderr)

    def on_diag_error(self, message: str):
        self.set_status_badge(self.diag_status_label, "error", "Error")
        self.append_diag_output(f"Diagnostics error: {message}")

    def run_quick_diagnostics(self):
        gateway = get_default_gateway()
        commands = []
        if gateway:
            commands.append(["ping", "-n", "2", "-w", "1000", gateway])
        commands.append(["ping", "-n", "2", "-w", "1000", "8.8.8.8"])
        commands.append(["tracert", "-d", "8.8.8.8"])
        self.run_diagnostic_commands("Quick diagnostics", commands)

    def run_ping_gateway_diag(self):
        gateway = get_default_gateway()
        if not gateway:
            self.append_diag_output("Gateway not found.")
            return
        self.run_diagnostic_commands(
            "Ping gateway",
            [["ping", "-n", "2", "-w", "1000", gateway]],
        )

    def run_ping_dns_diag(self):
        self.run_diagnostic_commands(
            "Ping 8.8.8.8",
            [["ping", "-n", "2", "-w", "1000", "8.8.8.8"]],
        )

    def run_traceroute_diag(self):
        target = self.diag_target_input.text().strip() or "8.8.8.8"
        self.run_diagnostic_commands(
            "Traceroute",
            [["tracert", "-d", target]],
        )

    def run_flush_dns_diag(self):
        self.run_diagnostic_commands(
            "Flush DNS",
            [["ipconfig", "/flushdns"]],
        )

    def run_renew_dhcp_diag(self):
        self.run_diagnostic_commands(
            "Renew DHCP",
            [["ipconfig", "/renew"]],
        )

    def set_device_buttons_enabled(self, enabled: bool):
        self.scan_arp_button.setEnabled(enabled)
        self.scan_network_button.setEnabled(enabled)
        self.scan_gateway_button.setEnabled(enabled)

    def scan_devices_arp(self):
        self.start_device_scan(None, allow_empty_subnet=True)

    def scan_devices_network(self):
        subnet = self.subnet_input.text().strip()
        if not subnet:
            self.on_devices_error("Subnet is empty.")
            return
        self.start_device_scan(subnet, allow_empty_subnet=False)

    def on_devices_result(self, devices: list[dict]):
        self.device_scan_in_flight = False
        self.set_device_buttons_enabled(True)

        now = datetime.now()
        now_text = now.strftime("%Y-%m-%d %H:%M:%S")
        now_ts = now.timestamp()

        previous_keys = self.current_device_keys.copy()
        scan_keys: set[str] = set()
        new_devices: list[dict] = []

        for device in devices:
            key = device.get("mac") or device.get("ip")
            if not key:
                continue
            scan_keys.add(key)
            entry = self.device_history.get(key)
            if entry is None:
                notes = self.device_notes.get(key, {})
                entry = {
                    "key": key,
                    "first_seen": now_text,
                    "first_seen_ts": now_ts,
                    "alias": notes.get("alias", ""),
                    "notes": notes.get("notes", ""),
                    "offline_alerted": False,
                }
                new_devices.append(device)
            entry.update(
                {
                    "ip": device.get("ip") or "",
                    "mac": device.get("mac") or "",
                    "type": device.get("type") or "",
                    "hostname": device.get("hostname") or "",
                    "vendor": device.get("vendor") or "",
                    "last_seen": now_text,
                    "last_seen_ts": now_ts,
                }
            )
            entry["offline_alerted"] = False
            self.device_history[key] = entry

        if self.device_scan_partial:
            current_keys = self.current_device_keys | scan_keys
        else:
            current_keys = scan_keys
        self.current_device_keys = current_keys
        if not self.device_scan_partial:
            new_count = len(current_keys - previous_keys)
            gone_count = len(previous_keys - current_keys)
            self.device_diff_label.setText(f"+{new_count} / -{gone_count}")

        if (
            not self.device_scan_partial
            and self.offline_device_alert_check.isChecked()
            and self.is_alert_schedule_active()
        ):
            offline_threshold = self.offline_after_spin.value() * 60
            for entry in self.device_history.values():
                key = entry.get("key")
                if not key or key in current_keys:
                    continue
                last_seen_ts = entry.get("last_seen_ts")
                if not last_seen_ts:
                    continue
                if now_ts - last_seen_ts >= offline_threshold and not entry.get(
                    "offline_alerted", False
                ):
                    entry["offline_alerted"] = True
                    message = f"Device offline: {entry.get('ip') or entry.get('mac') or key}"
                    self.append_monitor_log(message)
                    if hasattr(self, "tray"):
                        self.tray.showMessage(
                            "Wi-Fi Toolkit",
                            message,
                            QSystemTrayIcon.Information,
                            3000,
                        )
                    if self.device_sound_check.isChecked():
                        play_alert_sound()

        self.device_scan_partial = False
        self.refresh_device_table()

        self.set_status_badge(self.device_status_label, "idle", "Stopped")
        self.device_last_scan_label.setText(now_text)
        if new_devices and self.new_device_alert_check.isChecked() and self.is_alert_schedule_active():
            count = len(new_devices)
            message = f"{count} new device(s) detected."
            self.append_monitor_log(message)
            if hasattr(self, "tray"):
                self.tray.showMessage(
                    "Wi-Fi Toolkit",
                    message,
                    QSystemTrayIcon.Information,
                    3000,
                )
            if self.device_sound_check.isChecked():
                play_alert_sound()
        self.auto_export_devices()

    def on_devices_error(self, message: str):
        self.device_scan_in_flight = False
        self.device_scan_partial = False
        self.set_device_buttons_enabled(True)
        self.set_status_badge(self.device_status_label, "error", f"Error: {message}")
        if not self.device_history:
            self.devices_table.setRowCount(1)
            self.devices_table.setItem(0, 0, QTableWidgetItem(message))

    def export_devices(self):
        row_count = self.devices_table.rowCount()
        if row_count == 0:
            return
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Devices",
            "devices.csv",
            "CSV Files (*.csv)",
        )
        if not path:
            return
        rows = self.get_filtered_device_rows()
        self.export_device_rows_to_path(path, rows, "CSV")

    def auto_scan_devices(self):
        subnet = self.subnet_input.text().strip()
        self.devices_next_run_at = time.monotonic() + self.auto_scan_interval_spin.value()
        if not self.devices_countdown_timer.isActive():
            self.devices_countdown_timer.start(1000)
        self.update_devices_countdown()
        self.start_device_scan(subnet or None, allow_empty_subnet=True)

    def toggle_auto_scan(self, enabled: bool):
        if enabled:
            interval_ms = self.auto_scan_interval_spin.value() * 1000
            self.devices_timer.start(interval_ms)
            self.devices_next_run_at = time.monotonic() + self.auto_scan_interval_spin.value()
            self.devices_countdown_timer.start(1000)
            self.update_devices_countdown()
            self.auto_scan_devices()
        else:
            self.devices_timer.stop()
            self.devices_countdown_timer.stop()
            self.devices_next_run_at = None
            self.set_status_badge(self.device_status_label, "idle", "Stopped")
            self.device_next_scan_label.setText("-")

    def update_auto_scan_interval(self):
        if self.devices_timer.isActive():
            interval_ms = self.auto_scan_interval_spin.value() * 1000
            self.devices_timer.start(interval_ms)
            self.devices_next_run_at = time.monotonic() + self.auto_scan_interval_spin.value()
            self.update_devices_countdown()

    def clear_device_history(self):
        self.device_history.clear()
        self.current_device_keys.clear()
        self.devices_table.setRowCount(0)
        self.set_status_badge(self.device_status_label, "idle", "Stopped")
        self.device_last_scan_label.setText("-")
        self.device_diff_label.setText("-")

    def start_device_scan(
        self,
        subnet: str | None,
        allow_empty_subnet: bool,
        *,
        partial_scan: bool = False,
        filter_ips: set[str] | None = None,
        ping_targets: list[str] | None = None,
    ) -> None:
        if self.device_scan_in_flight:
            return
        if not subnet and not allow_empty_subnet:
            self.on_devices_error("Subnet is empty.")
            return
        timeout_ms = self.timeout_spin.value()
        resolve_names = self.resolve_names_check.isChecked()
        oui_db = self.oui_db if self.vendor_lookup_check.isChecked() else None
        self.device_scan_in_flight = True
        self.device_scan_partial = partial_scan
        self.set_status_badge(self.device_status_label, "running", "Running")
        self.set_device_buttons_enabled(False)

        def scan_job() -> list[dict]:
            if ping_targets:
                for target in ping_targets:
                    ping_host_once(target, timeout_ms)
            result = run_arp_scan(subnet, timeout_ms, resolve_names, oui_db)
            if filter_ips:
                result = [device for device in result if device.get("ip") in filter_ips]
            return result

        self.start_worker(scan_job, self.on_devices_result, self.on_devices_error)

    def update_devices_countdown(self):
        if not self.auto_scan_check.isChecked() or self.devices_next_run_at is None:
            self.device_next_scan_label.setText("-")
            return
        remaining = int(self.devices_next_run_at - time.monotonic())
        if remaining < 0:
            remaining = 0
        self.device_next_scan_label.setText(f"{remaining} s")
        if not self.device_scan_in_flight and not self.device_status_label.text().startswith("Error"):
            self.set_status_badge(self.device_status_label, "idle", "Stopped")

    def scan_gateway_only(self):
        gateway = get_default_gateway()
        if not gateway:
            self.on_devices_error("Default gateway not found.")
            return
        self.start_device_scan(
            None,
            allow_empty_subnet=True,
            partial_scan=True,
            filter_ips={gateway},
            ping_targets=[gateway],
        )

    def apply_scan_profile(self, profile: str):
        if profile == "Fast":
            self.resolve_names_check.setChecked(False)
            self.vendor_lookup_check.setChecked(False)
            self.timeout_spin.setValue(120)
        elif profile == "Deep":
            self.resolve_names_check.setChecked(True)
            self.vendor_lookup_check.setChecked(True)
            self.timeout_spin.setValue(750)
        else:
            self.resolve_names_check.setChecked(True)
            self.vendor_lookup_check.setChecked(True)
            self.timeout_spin.setValue(250)

    def get_filtered_device_rows(self) -> list[dict]:
        query = self.device_filter_input.text().strip().lower()
        status_filter = self.device_status_filter.currentText()
        rows = sorted(
            self.device_history.values(),
            key=lambda item: item.get("last_seen_ts", 0),
            reverse=True,
        )
        filtered: list[dict] = []
        for entry in rows:
            key = entry.get("key")
            if not key:
                continue
            status_text = "Online" if key in self.current_device_keys else "Offline"
            if status_filter != "All" and status_text != status_filter:
                continue
            if query:
                haystack = " ".join(
                    [
                        entry.get("ip", ""),
                        entry.get("mac", ""),
                        entry.get("type", ""),
                        entry.get("hostname", ""),
                        entry.get("notes", ""),
                        entry.get("vendor", ""),
                        entry.get("alias", ""),
                        status_text,
                    ]
                ).lower()
                if query not in haystack:
                    continue
            entry_copy = dict(entry)
            entry_copy["status"] = status_text
            filtered.append(entry_copy)
        return filtered

    def refresh_device_table(self):
        rows = self.get_filtered_device_rows()
        self.devices_table_updating = True
        self.devices_table.setRowCount(len(rows))
        for row, entry in enumerate(rows):
            key = entry.get("key", "")
            status_text = entry.get("status", "")
            if self.dark_mode_enabled:
                online_bg = QColor("#0b2f2a")
                offline_bg = QColor("#0b1220")
            else:
                online_bg = QColor("#ecfdf3")
                offline_bg = QColor("#f8fafc")
            if status_text == "Online":
                row_bg = online_bg
            elif status_text == "Offline":
                row_bg = offline_bg
            else:
                row_bg = None
            self.devices_table.setItem(row, 0, self.make_device_item(entry.get("ip", "")))
            self.devices_table.setItem(row, 1, self.make_device_item(entry.get("mac", "")))
            self.devices_table.setItem(row, 2, self.make_device_item(entry.get("type", "")))
            self.devices_table.setItem(
                row, 3, self.make_device_item(entry.get("hostname", ""))
            )
            alias_item = self.make_device_item(entry.get("alias", ""), editable=True)
            alias_item.setData(Qt.UserRole, key)
            self.devices_table.setItem(row, 4, alias_item)
            notes_item = self.make_device_item(entry.get("notes", ""), editable=True)
            notes_item.setData(Qt.UserRole, key)
            self.devices_table.setItem(row, 5, notes_item)
            self.devices_table.setItem(
                row, 6, self.make_device_item(entry.get("vendor", ""))
            )
            self.devices_table.setItem(
                row, 7, self.make_device_item(entry.get("status", ""))
            )
            self.devices_table.setItem(
                row, 8, self.make_device_item(entry.get("last_seen", ""))
            )
            if row_bg:
                for col in range(self.devices_table.columnCount()):
                    item = self.devices_table.item(row, col)
                    if item:
                        item.setBackground(row_bg)
        self.devices_table_updating = False

    def make_device_item(self, text: str, editable: bool = False) -> QTableWidgetItem:
        item = QTableWidgetItem(text)
        flags = Qt.ItemIsSelectable | Qt.ItemIsEnabled
        if editable:
            flags |= Qt.ItemIsEditable
        item.setFlags(flags)
        return item

    def on_device_item_changed(self, item: QTableWidgetItem):
        if self.devices_table_updating:
            return
        if item.column() not in (4, 5):
            return
        key = item.data(Qt.UserRole)
        if not key:
            return
        entry = self.device_history.get(key)
        if not entry:
            return
        text = item.text().strip()
        if item.column() == 4:
            entry["alias"] = text
        else:
            entry["notes"] = text
        self.device_notes[key] = {
            "alias": entry.get("alias", ""),
            "notes": entry.get("notes", ""),
        }
        self.save_device_notes()

    def select_device_export_path(self):
        suffix = "csv" if self.auto_export_format.currentText() == "CSV" else "jsonl"
        filename = f"devices_{datetime.now().strftime('%Y%m%d')}.{suffix}"
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Select Auto Export Path",
            filename,
            "CSV Files (*.csv);;JSON Lines (*.jsonl)",
        )
        if path:
            self.auto_export_path_input.setText(path)

    def get_default_device_export_path(self) -> Path:
        log_dir = get_app_dir() / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        suffix = "csv" if self.auto_export_format.currentText() == "CSV" else "jsonl"
        filename = f"devices_{datetime.now().strftime('%Y%m%d')}.{suffix}"
        return log_dir / filename

    def auto_export_devices(self):
        if not self.auto_export_check.isChecked():
            return
        path_text = self.auto_export_path_input.text().strip()
        path = Path(path_text) if path_text else self.get_default_device_export_path()
        if not path_text:
            self.auto_export_path_input.setText(str(path))
        rows = self.get_filtered_device_rows()
        self.export_device_rows_to_path(path, rows, self.auto_export_format.currentText())

    def export_device_rows_to_path(self, path: Path | str, rows: list[dict], fmt: str):
        if not rows:
            return
        fmt_upper = fmt.upper()
        if fmt_upper == "JSONL":
            with open(path, "a", encoding="utf-8") as handle:
                for entry in rows:
                    payload = {
                        "ip": entry.get("ip", ""),
                        "mac": entry.get("mac", ""),
                        "type": entry.get("type", ""),
                        "hostname": entry.get("hostname", ""),
                        "alias": entry.get("alias", ""),
                        "notes": entry.get("notes", ""),
                        "vendor": entry.get("vendor", ""),
                        "status": entry.get("status", ""),
                        "last_seen": entry.get("last_seen", ""),
                    }
                    handle.write(json.dumps(payload, ensure_ascii=True) + "\n")
            return

        with open(path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(
                [
                    "ip",
                    "mac",
                    "type",
                    "hostname",
                    "alias",
                    "notes",
                    "vendor",
                    "status",
                    "last_seen",
                ]
            )
            for entry in rows:
                writer.writerow(
                    [
                        entry.get("ip", ""),
                        entry.get("mac", ""),
                        entry.get("type", ""),
                        entry.get("hostname", ""),
                        entry.get("alias", ""),
                        entry.get("notes", ""),
                        entry.get("vendor", ""),
                        entry.get("status", ""),
                        entry.get("last_seen", ""),
                    ]
                )
    def update_oui_status(self):
        if self.oui_db:
            self.oui_status_label.setText(f"Vendor DB: {len(self.oui_db)} entries")
        else:
            self.oui_status_label.setText("Vendor DB: not loaded")

    def download_oui(self):
        self.download_oui_button.setEnabled(False)
        self.oui_status_label.setText("Vendor DB: downloading...")
        self.start_worker(
            lambda: download_oui_database(self.oui_path),
            self.on_oui_download_result,
            self.on_oui_download_error,
        )

    def on_oui_download_result(self, _):
        self.reload_oui()
        self.download_oui_button.setEnabled(True)

    def on_oui_download_error(self, message: str):
        self.append_monitor_log(f"OUI download failed: {message}")
        self.update_oui_status()
        self.download_oui_button.setEnabled(True)

    def reload_oui(self):
        self.oui_db = load_oui_database(self.oui_path)
        self.update_oui_status()

    def append_monitor_log(self, message: str):
        timestamp = QDateTime.currentDateTime().toString("HH:mm:ss")
        self.monitor_log.append(f"[{timestamp}] {message}")

    def start_worker(self, func, on_success, on_error):
        thread = QThread(self)
        worker = Worker(func)
        worker.moveToThread(thread)

        thread.started.connect(worker.run)
        worker.finished.connect(on_success)
        worker.error.connect(on_error)
        worker.finished.connect(thread.quit)
        worker.error.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        worker.error.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)

        self.active_workers.append((thread, worker))

        def cleanup_worker():
            for idx, (tracked_thread, tracked_worker) in enumerate(self.active_workers):
                if tracked_thread is thread and tracked_worker is worker:
                    self.active_workers.pop(idx)
                    break

        thread.finished.connect(cleanup_worker)

        thread.start()


def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
