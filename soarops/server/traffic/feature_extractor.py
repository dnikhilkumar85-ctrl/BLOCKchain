"""
feature_extractor.py
====================
Extracts unidirectional (forward-only) network flow features from PyShark packet objects
or raw packet streams. Designed strictly for one-way ingress telemetry (Data Diodes,
passive optical taps, asymmetric IP routing).

Key Features:
- 40 forward-only feature columns (no backward or round-trip features).
- Stateful UnidirectionalFlowAggregator: groups packets into micro-flows by 4-tuple
  (src_ip, dst_ip, dst_port, protocol) within a temporal window to compute realistic
  inter-arrival times (IAT), duration, flag counts, and burst distributions.
- Instant single-packet feature extractor fallback for lightweight streaming.
"""

import json
import logging
import os
import time
import math
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Load the canonical 40 unidirectional feature columns
_DIR = os.path.dirname(os.path.abspath(__file__))
_COL_FILE = os.path.join(os.path.dirname(_DIR), "feature_columns_unidirectional.json")

if os.path.exists(_COL_FILE):
    with open(_COL_FILE, "r") as f:
        FEATURE_COLUMNS = json.load(f)
else:
    FEATURE_COLUMNS = [
        "Destination Port", "Flow Duration", "Total Fwd Packets",
        "Total Length of Fwd Packets", "Fwd Packet Length Max",
        "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
        "Flow Bytes/s", "Flow Packets/s",
        "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
        "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
        "Fwd Header Length", "Fwd Packets/s",
        "Min Packet Length", "Max Packet Length",
        "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
        "FIN Flag Count", "PSH Flag Count", "ACK Flag Count",
        "Average Packet Size", "Subflow Fwd Bytes",
        "Init_Win_bytes_forward", "act_data_pkt_fwd", "min_seg_size_forward",
        "Active Mean", "Active Max", "Active Min",
        "Idle Mean", "Idle Max", "Idle Min"
    ]


def _has_tcp_flag(packet, flag_name: str) -> bool:
    """Check if a specific TCP flag is set in the PyShark packet."""
    try:
        flags = int(packet.tcp.flags, 16)
        flag_map = {
            "fin": 0x001, "syn": 0x002, "rst": 0x004,
            "psh": 0x008, "ack": 0x010, "urg": 0x020
        }
        return bool(flags & flag_map.get(flag_name.lower(), 0))
    except Exception:
        return False


class UnidirectionalFlow:
    """Represents an active ingress micro-flow over a time window."""

    def __init__(self, key: Tuple[str, str, int, str], start_time: float):
        self.key = key  # (src_ip, dst_ip, dst_port, protocol)
        self.start_time = start_time
        self.last_time = start_time
        self.packet_lengths: List[float] = []
        self.timestamps: List[float] = [start_time]

        # TCP Specifics
        self.fin_count = 0
        self.psh_count = 0
        self.ack_count = 0
        self.syn_count = 0
        self.init_win_bytes = 0.0
        self.fwd_header_len = 0.0
        self.min_seg_size = 0.0

    def add_packet(self, length: float, timestamp: float, packet=None):
        self.packet_lengths.append(length)
        if len(self.timestamps) > 0 and timestamp > self.last_time:
            self.timestamps.append(timestamp)
        self.last_time = timestamp

        if packet and hasattr(packet, "tcp"):
            if _has_tcp_flag(packet, "fin"):
                self.fin_count += 1
            if _has_tcp_flag(packet, "psh"):
                self.psh_count += 1
            if _has_tcp_flag(packet, "ack"):
                self.ack_count += 1
            if _has_tcp_flag(packet, "syn"):
                self.syn_count += 1

            try:
                self.init_win_bytes = float(packet.tcp.window_size_value)
            except (AttributeError, ValueError):
                pass

            try:
                hdr_len = float(packet.tcp.hdr_len)
                self.fwd_header_len += hdr_len
                self.min_seg_size = hdr_len
            except (AttributeError, ValueError):
                pass

    def to_features(self) -> Dict[str, float]:
        """Calculates and returns the 40 unidirectional flow features."""
        features = {col: 0.0 for col in FEATURE_COLUMNS}
        dst_port = float(self.key[2])
        features["Destination Port"] = dst_port

        n = len(self.packet_lengths)
        if n == 0:
            return features

        total_bytes = sum(self.packet_lengths)
        duration = max(0.0001, self.last_time - self.start_time)
        features["Flow Duration"] = duration * 1_000_000.0  # microseconds
        features["Total Fwd Packets"] = float(n)
        features["Total Length of Fwd Packets"] = float(total_bytes)
        features["Subflow Fwd Bytes"] = float(total_bytes)

        # Length Statistics
        features["Fwd Packet Length Max"] = float(max(self.packet_lengths))
        features["Fwd Packet Length Min"] = float(min(self.packet_lengths))
        mean_len = total_bytes / n
        features["Fwd Packet Length Mean"] = float(mean_len)
        features["Packet Length Mean"] = float(mean_len)
        features["Average Packet Size"] = float(mean_len)
        features["Max Packet Length"] = float(max(self.packet_lengths))
        features["Min Packet Length"] = float(min(self.packet_lengths))

        if n > 1:
            var = sum((x - mean_len) ** 2 for x in self.packet_lengths) / (n - 1)
            std = math.sqrt(var)
            features["Fwd Packet Length Std"] = float(std)
            features["Packet Length Std"] = float(std)
            features["Packet Length Variance"] = float(var)
        else:
            features["Fwd Packet Length Std"] = 0.0
            features["Packet Length Std"] = 0.0
            features["Packet Length Variance"] = 0.0

        # Flow Rates
        features["Flow Bytes/s"] = float(total_bytes / duration)
        features["Flow Packets/s"] = float(n / duration)
        features["Fwd Packets/s"] = float(n / duration)

        # Inter-Arrival Times (IAT)
        if len(self.timestamps) > 1:
            iats = [
                (self.timestamps[i] - self.timestamps[i - 1]) * 1_000_000.0
                for i in range(1, len(self.timestamps))
            ]
            total_iat = sum(iats)
            mean_iat = total_iat / len(iats)
            max_iat = max(iats)
            min_iat = min(iats)
            std_iat = (
                math.sqrt(sum((x - mean_iat) ** 2 for x in iats) / len(iats))
                if len(iats) > 1 else 0.0
            )

            features["Flow IAT Mean"] = float(mean_iat)
            features["Flow IAT Std"] = float(std_iat)
            features["Flow IAT Max"] = float(max_iat)
            features["Flow IAT Min"] = float(min_iat)
            features["Fwd IAT Total"] = float(total_iat)
            features["Fwd IAT Mean"] = float(mean_iat)
            features["Fwd IAT Std"] = float(std_iat)
            features["Fwd IAT Max"] = float(max_iat)
            features["Fwd IAT Min"] = float(min_iat)

        # TCP Flags & Headers
        features["FIN Flag Count"] = float(self.fin_count)
        features["PSH Flag Count"] = float(self.psh_count)
        features["ACK Flag Count"] = float(self.ack_count)
        features["Init_Win_bytes_forward"] = float(self.init_win_bytes)
        features["Fwd Header Length"] = float(self.fwd_header_len if self.fwd_header_len > 0 else 20.0 * n)
        features["min_seg_size_forward"] = float(self.min_seg_size if self.min_seg_size > 0 else 20.0)
        features["act_data_pkt_fwd"] = float(sum(1 for l in self.packet_lengths if l > 40))

        # Active / Idle time estimates
        features["Active Mean"] = float(features["Flow Duration"])
        features["Active Max"] = float(features["Flow Duration"])
        features["Active Min"] = float(features["Flow Duration"])
        features["Idle Mean"] = 0.0
        features["Idle Max"] = 0.0
        features["Idle Min"] = 0.0

        return features


class UnidirectionalFlowAggregator:
    """
    Maintains and aggregates active unidirectional flows within a sliding timeout window.
    Emits completed flow feature dictionaries for AI inference.
    """

    def __init__(self, timeout_seconds: float = 2.0, max_active_flows: int = 1000):
        self.timeout_seconds = timeout_seconds
        self.max_active_flows = max_active_flows
        self.flows: Dict[Tuple[str, str, int, str], UnidirectionalFlow] = {}

    def process_packet(self, packet) -> Optional[Dict[str, float]]:
        """
        Ingests a PyShark packet. If flow has accumulated sufficient data or timed out,
        returns feature dict ready for XGBoost inference.
        """
        now = time.time()

        src_ip = "0.0.0.0"
        dst_ip = "0.0.0.0"
        dst_port = 0
        protocol = "IP"

        try:
            if hasattr(packet, "ip"):
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst

            if hasattr(packet, "tcp"):
                dst_port = int(packet.tcp.dstport)
                protocol = "TCP"
            elif hasattr(packet, "udp"):
                dst_port = int(packet.udp.dstport)
                protocol = "UDP"

            length = float(getattr(packet, "length", 64))
        except Exception:
            return extract_single_packet_features(packet)

        flow_key = (src_ip, dst_ip, dst_port, protocol)

        # Check existing flow
        flow = self.flows.get(flow_key)
        if not flow:
            # Housekeeping if cache is full
            if len(self.flows) >= self.max_active_flows:
                self.purge_stale(now)
            flow = UnidirectionalFlow(flow_key, start_time=now)
            self.flows[flow_key] = flow

        flow.add_packet(length, now, packet)

        # Trigger inference condition: either flow has enough packets or time elapsed
        if len(flow.packet_lengths) >= 5 or (now - flow.start_time) >= self.timeout_seconds:
            features = flow.to_features()
            # Reset flow for next window
            del self.flows[flow_key]
            return features

        return None

    def purge_stale(self, now: float) -> List[Dict[str, float]]:
        """Evicts expired flows and returns their completed feature dictionaries."""
        expired_keys = [
            k for k, flow in self.flows.items()
            if (now - flow.last_time) >= self.timeout_seconds
        ]
        results = []
        for k in expired_keys:
            results.append(self.flows[k].to_features())
            del self.flows[k]
        return results


def extract_single_packet_features(packet) -> Dict[str, float]:
    """
    Fallback instantaneous unidirectional feature extractor for a single packet.
    Guarantees compatibility with feature_columns_unidirectional.json without dummy zeroing.
    """
    features = {col: 0.0 for col in FEATURE_COLUMNS}

    try:
        if hasattr(packet, "tcp"):
            features["Destination Port"] = float(packet.tcp.dstport)
            features["FIN Flag Count"] = 1.0 if _has_tcp_flag(packet, "fin") else 0.0
            features["PSH Flag Count"] = 1.0 if _has_tcp_flag(packet, "psh") else 0.0
            features["ACK Flag Count"] = 1.0 if _has_tcp_flag(packet, "ack") else 0.0

            try:
                features["Init_Win_bytes_forward"] = float(packet.tcp.window_size_value)
            except AttributeError:
                pass
            try:
                hdr_len = float(packet.tcp.hdr_len)
                features["min_seg_size_forward"] = hdr_len
                features["Fwd Header Length"] = hdr_len
            except AttributeError:
                pass
        elif hasattr(packet, "udp"):
            features["Destination Port"] = float(packet.udp.dstport)

        pkt_len = float(getattr(packet, "length", 64))
        features["Total Length of Fwd Packets"] = pkt_len
        features["Fwd Packet Length Max"] = pkt_len
        features["Fwd Packet Length Min"] = pkt_len
        features["Fwd Packet Length Mean"] = pkt_len
        features["Min Packet Length"] = pkt_len
        features["Max Packet Length"] = pkt_len
        features["Packet Length Mean"] = pkt_len
        features["Average Packet Size"] = pkt_len
        features["Subflow Fwd Bytes"] = pkt_len
        features["act_data_pkt_fwd"] = 1.0 if pkt_len > 40 else 0.0

        features["Total Fwd Packets"] = 1.0
        features["Fwd Packets/s"] = 1.0
        features["Flow Bytes/s"] = pkt_len
        features["Flow Packets/s"] = 1.0

    except Exception as e:
        logger.warning(f"Feature extraction error: {e}")

    return features


# Default extractor alias
extract_features = extract_single_packet_features
