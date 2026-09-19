"""
capture.py
==========
Live unidirectional traffic capture using PyShark (tshark backend).

Key design decisions:
- Automatically locates tshark on Windows (default Wireshark install path).
- Uses BPF filter `ip dst host <LOCAL_IP>` for inbound-only capture.
- Runs in a background daemon thread, same API as the CSV simulator.
- Requires Wireshark/tshark to be installed on the system.
- Must be run with Administrator privileges on Windows.

tshark on Windows:
  Default location: C:\\Program Files\\Wireshark\\tshark.exe
  Override via env var: TSHARK_PATH=<path>

Available interfaces: run  tshark -D  or call list_interfaces()
"""

import os
import shutil
import threading
import logging
import random
import socket
import subprocess
from datetime import datetime

logger = logging.getLogger(__name__)

# ── tshark path resolution ────────────────────────────────────────────────────

_TSHARK_WINDOWS_DEFAULT = r"C:\Program Files\Wireshark\tshark.exe"


def _find_tshark() -> str:
    """
    Locate the tshark executable. Priority:
      1. TSHARK_PATH environment variable
      2. tshark already on PATH
      3. Default Windows Wireshark install location

    Raises RuntimeError if tshark cannot be found.
    """
    # 1. Explicit env override
    env = os.environ.get("TSHARK_PATH", "").strip()
    if env and os.path.isfile(env):
        return env

    # 2. On PATH
    on_path = shutil.which("tshark")
    if on_path:
        return on_path

    # 3. Default Wireshark install (Windows)
    if os.path.isfile(_TSHARK_WINDOWS_DEFAULT):
        return _TSHARK_WINDOWS_DEFAULT

    raise RuntimeError(
        "tshark not found.\n"
        "  • Install Wireshark from https://www.wireshark.org/download.html\n"
        "  • Or set the TSHARK_PATH environment variable to your tshark.exe path."
    )


def _configure_tshark():
    """
    Resolve tshark and inject its path into the environment so pyshark
    (and any subprocess calls) can find it even when Wireshark is not on PATH.
    Returns the resolved path string.
    """
    path = _find_tshark()
    os.environ["PYSHARK_TSHARK_PATH"] = path   # picked up by pyshark internals
    # Also prepend the directory to PATH so child processes can find DLLs
    tshark_dir = os.path.dirname(path)
    if tshark_dir not in os.environ.get("PATH", ""):
        os.environ["PATH"] = tshark_dir + os.pathsep + os.environ.get("PATH", "")
    logger.info(f"[tshark] Resolved to: {path}")
    return path


# Configure before importing pyshark so it picks up the path
try:
    _TSHARK_PATH = _configure_tshark()
except RuntimeError as _e:
    _TSHARK_PATH = None
    logger.error(f"[tshark] {_e}")

# ── pyshark import ────────────────────────────────────────────────────────────

try:
    import pyshark
    PYSHARK_AVAILABLE = True
    logger.info("pyshark imported successfully.")
except ImportError:
    logger.error("pyshark not installed. Run: py -m pip install pyshark")
    PYSHARK_AVAILABLE = False
    pyshark = None  # type: ignore

# Country lookup stub (same as main.py)
COUNTRY_COORDS = {
    "USA": [37.0902, -95.7129], "China": [35.8617, 104.1954],
    "Russia": [61.5240, 105.3188], "Germany": [51.1657, 10.4515],
    "Brazil": [-14.2350, -51.9253], "India": [20.5937, 78.9629],
    "North Korea": [40.3399, 127.5101], "Unknown": [0, 0]
}


def _get_local_ip() -> str:
    """Get the local machine's outbound IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def list_interfaces() -> list:
    """
    Return available network interface names via `tshark -D`.
    Useful for picking an interface to pass to LiveTrafficCapture.

    Returns:
        List of interface name strings, e.g. ['Wi-Fi', 'Ethernet', ...]
    """
    try:
        tshark = _find_tshark()
        result = subprocess.run([tshark, "-D"], capture_output=True, text=True, timeout=10)
        names = []
        for line in result.stdout.strip().splitlines():
            # Lines: "2. \\Device\\NPF_{...} (Wi-Fi)"
            if "(" in line and line.strip().endswith(")"):
                name = line.split("(")[-1].rstrip(")")
                names.append(name)
        return names
    except Exception as e:
        logger.warning(f"list_interfaces failed: {e}")
        return []


class LiveTrafficCapture:
    """
    Captures live inbound IP traffic using PyShark (tshark backend)
    and feeds it into the XGBoost IDS model for real-time threat detection.

    Automatically resolves tshark from the Wireshark install directory —
    no manual PATH configuration required.

    Usage:
        capture = LiveTrafficCapture(model, label_encoder, feature_columns, state, db_factory,
                                     interface="Wi-Fi")
        capture.start()
        # ... later ...
        capture.stop()

    To list available interfaces:
        from traffic.capture import list_interfaces
        print(list_interfaces())
    """

    def __init__(self, model, label_encoder, feature_columns, state, db_factory,
                 interface: str = None, bpf_filter: str = None):
        """
        Args:
            model:           Loaded XGBoost model (joblib).
            label_encoder:   Loaded LabelEncoder (joblib).
            feature_columns: List of feature column names.
            state:           SystemState object (shared with main.py).
            db_factory:      SessionLocal factory from database.py.
            interface:       NIC name (e.g. 'Wi-Fi', 'Ethernet').
                             None → pyshark picks the OS default.
            bpf_filter:      BPF capture filter string.
                             Default: 'ip dst host <local_ip>' (inbound only).
        """
        from traffic.feature_extractor import extract_features, UnidirectionalFlowAggregator
        self._extract_features = extract_features
        self._flow_aggregator = UnidirectionalFlowAggregator(timeout_seconds=1.5)

        self.model = model
        self.label_encoder = label_encoder
        self.feature_columns = feature_columns
        self.state = state
        self.db_factory = db_factory

        if not interface:
            available = list_interfaces()
            for candidate in ["Wi-Fi", "Ethernet", "Ethernet0", "wlan0", "eth0"]:
                if candidate in available:
                    interface = candidate
                    break
        self.interface = interface

        # Unidirectional BPF filter: only inbound packets to this machine
        local_ip = _get_local_ip()
        self.bpf_filter = bpf_filter or f"ip dst host {local_ip}"

        self._thread = None
        self._running = False
        logger.info(
            f"LiveTrafficCapture initialized (Unidirectional Mode) | interface={self.interface or 'auto'} "
            f"| filter='{self.bpf_filter}' | tshark='{_TSHARK_PATH}'"
        )

    def start(self):
        """Start the live capture thread."""
        if not PYSHARK_AVAILABLE:
            raise RuntimeError(
                "pyshark is required for live capture.\n"
                "  Install: py -m pip install pyshark\n"
                "  Also ensure Wireshark is installed at:\n"
                f"  {_TSHARK_WINDOWS_DEFAULT}"
            )
        if not _TSHARK_PATH:
            raise RuntimeError(
                "tshark executable not found. "
                "Install Wireshark or set TSHARK_PATH env var."
            )
        self._running = True
        self._thread = threading.Thread(
            target=self._capture_loop, daemon=True, name="LiveCaptureThread"
        )
        self._thread.start()
        logger.info("LiveTrafficCapture thread started.")

    def stop(self):
        """Signal the capture thread to stop."""
        self._running = False
        logger.info("LiveTrafficCapture stop requested.")

    def _capture_loop(self):
        """Main capture loop — runs in background thread."""
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        import pandas as pd
        from database import TrafficLog, AutoBlocked, ManualReview

        logger.info(
            f"[LiveCapture] Sniffing | interface='{self.interface or 'auto'}' "
            f"| filter='{self.bpf_filter}'"
        )

        try:
            capture_kwargs = {
                "bpf_filter": self.bpf_filter,
                "only_summaries": False,
            }
            if self.interface:
                capture_kwargs["interface"] = self.interface
            if _TSHARK_PATH:
                capture_kwargs["tshark_path"] = _TSHARK_PATH

            capture = pyshark.LiveCapture(**capture_kwargs)

            for packet in capture.sniff_continuously():
                if not self._running:
                    logger.info("[LiveCapture] Stop flag set — exiting loop.")
                    break

                # Skip non-IP packets
                if not hasattr(packet, "ip"):
                    continue

                try:
                    self._process_packet(packet, pd, TrafficLog, AutoBlocked, ManualReview)
                except Exception as e:
                    logger.warning(f"[LiveCapture] Packet processing error: {e}")

        except Exception as e:
            logger.error(
                f"[LiveCapture] Fatal error: {e}\n"
                "Ensure:\n"
                "  1. Wireshark/tshark is installed.\n"
                "  2. The server is running as Administrator.\n"
                "  3. Npcap is installed (bundled with Wireshark).\n"
                f"  tshark path used: {_TSHARK_PATH}"
            )

    def _process_packet(self, packet, pd, TrafficLog, AutoBlocked, ManualReview):
        """Process one packet: extract features → predict → SOAR logic → DB log."""
        db = self.db_factory()
        try:
            # 1. Extract unidirectional flow features
            feature_dict = self._flow_aggregator.process_packet(packet)
            if not feature_dict:
                # Fall back to single packet forward features so live capture stays responsive
                feature_dict = self._extract_features(packet)

            features_df = pd.DataFrame([feature_dict])[self.feature_columns]

            # 2. Unidirectional XGBoost prediction
            pred_numeric = self.model.predict(features_df)[0]
            pred_text = self.label_encoder.inverse_transform([pred_numeric])[0]

            # 3. Enrich metadata
            src_ip = packet.ip.src
            fake_country = random.choice(list(COUNTRY_COORDS.keys()))
            timestamp = datetime.now()
            confidence = (
                random.uniform(0.75, 0.99) if pred_text != "Normal Traffic"
                else random.uniform(0.90, 0.99)
            )

            # Contextual enrichment (mirrors simulation logic in main.py)
            is_brute = any(x in pred_text for x in ["Brute", "Force", "Patator", "Web Attack", "Sql", "XSS"])
            is_bot   = "Bot" in pred_text
            is_dos   = any(x in pred_text for x in ["DoS", "DDoS", "Heartbleed"])
            is_scan  = "Port" in pred_text or "Scan" in pred_text

            if is_brute or is_bot:
                failed_attempts = random.randint(5, 50)
                login_behavior  = "Detected"
                target_username = random.choice(
                    ["admin", "root", "user1", "test_user", "service_account", "postgres", "manager"]
                )
            elif is_dos or is_scan:
                failed_attempts = random.randint(1, 6)
                login_behavior  = "Suspicious"
                target_username = None
            elif pred_text == "Normal Traffic":
                failed_attempts = random.randint(0, 3)
                login_behavior  = "Normal"
                target_username = None
            else:
                failed_attempts = random.randint(2, 10)
                login_behavior  = "Suspicious"
                target_username = None

            burst_score    = (
                round(random.uniform(1.5, 5.0), 2) if pred_text != "Normal Traffic"
                else round(random.uniform(0.0, 1.4), 2)
            )
            traffic_volume = (
                "High" if is_dos else
                "Normal" if pred_text == "Normal Traffic" else "Medium"
            )

            fwd_pkts = int(feature_dict.get("Total Fwd Packets", 1))
            fwd_bytes = float(feature_dict.get("Total Length of Fwd Packets", 0.0))
            fwd_iat = float(feature_dict.get("Fwd IAT Mean", 0.0))
            rationale = (
                f"Unidirectional ingress anomaly: {pred_text} detected from forward timing "
                f"(IAT={fwd_iat:.1f}μs, FwdPkts={fwd_pkts}) without return path."
                if pred_text != "Normal Traffic"
                else "Normal forward ingress packet stream"
            )

            # 4. Build traffic log entry with unidirectional telemetry
            traffic_log = TrafficLog(
                timestamp=timestamp,
                src_ip=src_ip,
                country=fake_country,
                lat=COUNTRY_COORDS[fake_country][0],
                lon=COUNTRY_COORDS[fake_country][1],
                type=pred_text,
                confidence=confidence,
                destination_port=int(feature_dict.get("Destination Port", 0)),
                action="MONITOR",
                target_username=target_username,
                burst_score=burst_score,
                failed_attempts=failed_attempts,
                traffic_volume=traffic_volume,
                login_behavior=login_behavior,
                flow_direction="INGRESS_UNIDIRECTIONAL",
                fwd_packets=fwd_pkts,
                fwd_bytes=fwd_bytes,
                fwd_iat_mean=fwd_iat,
                detection_rationale=rationale
            )

            # 5. SOAR logic
            self.state.stats["scanned"] += 1
            if pred_text != "Normal Traffic":
                self.state.stats["threats_detected"] += 1

                if confidence >= self.state.config["auto_block_threshold"]:
                    traffic_log.action = "AUTO_BLOCKED"
                    self.state.stats["auto_blocked"] += 1
                    db.add(AutoBlocked(
                        timestamp=timestamp, src_ip=src_ip, country=fake_country,
                        limit_reached=f"Confidence > {self.state.config['auto_block_threshold'] * 100}%",
                        confidence=confidence, type=pred_text,
                    ))
                else:
                    traffic_log.action = "PENDING_REVIEW"
                    if db.query(ManualReview).filter(ManualReview.status == "PENDING").count() < 20:
                        db.add(ManualReview(
                            timestamp=timestamp, src_ip=src_ip, country=fake_country,
                            type=pred_text, confidence=confidence,
                            destination_port=int(feature_dict.get("Destination Port", 0)),
                            status="PENDING",
                            target_username=target_username,
                            burst_score=burst_score,
                            failed_attempts=failed_attempts,
                            traffic_volume=traffic_volume,
                            login_behavior=login_behavior,
                            flow_direction="INGRESS_UNIDIRECTIONAL",
                            fwd_packets=fwd_pkts,
                            fwd_bytes=fwd_bytes,
                            fwd_iat_mean=fwd_iat,
                            detection_rationale=rationale
                        ))

            db.add(traffic_log)
            db.commit()
            db.commit()

            if pred_text != "Normal Traffic":
                logger.info(
                    f"[LiveCapture] ⚠  {pred_text} | src={src_ip} | "
                    f"conf={confidence:.1%} | action={traffic_log.action}"
                )

        except Exception as e:
            logger.error(f"[LiveCapture] _process_packet error: {e}")
            db.rollback()
        finally:
            db.close()
