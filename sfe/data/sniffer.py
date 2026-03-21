"""
sfe.data.sniffer
----------------

Sniffer class for live packet capture and session extraction using Packet and Session classes.
"""

import threading
import time
from collections import defaultdict, deque
from pathlib import Path
from statistics import mean, stdev, variance
from typing import List, Optional

import numpy as np
from loguru import logger
from scapy.all import get_if_list, sniff

from sfe.core.packet import Packet
from sfe.core.session.session import Session
from sfe.defs.session_flow import SessionFlow


class SessionSniffer:
    """
    SessionSniffer is a high-level sniffer and sessionizer for network traffic.

    It can:
    - Capture packets from a live network interface or read from a pcap file.
    - Group packets into sessions (flows) using a 5-tuple (src IP, dst IP, src port, dst port, protocol).
    - Maintain a per-session buffer for real-time or windowed analysis.
    - Extract rich flow/session features (CICFlowMeter-style) for each session using the SessionFlow dataclass.
    - Optionally write captured packets to a pcap file.
    - Support both batch (offline) and continuous (live) processing.
    - Provide thread-based background processing for scalable feature extraction.

    Usage:
        # For offline pcap analysis:
        sniffer = SessionSniffer(pcap_path=Path('file.pcap'))
        sniffer.sniff_packets()
        sessions = sniffer.group_sessions()
        for session in sessions:
            features = sniffer.create_session_flow(session)

        # For live capture:
        sniffer = SessionSniffer(iface='eth0')
        sniffer.sniff_continuous()

    Args:
        iface (str, optional): Network interface name for live capture.
        pcap_path (Path, optional): Path to a pcap file for offline analysis.
        buffer_window (int): Time window (seconds) for session buffer retention.
        write_pcap (Path, optional): If set, write captured packets to this pcap file.
        buffer_maxlen (int): Max number of packets to keep per session buffer.
    """

    def __init__(
        self,
        iface: Optional[str] = None,
        pcap_path: Optional[Path] = None,
        buffer_window: int = 60,
        write_pcap: Optional[Path] = None,
        buffer_maxlen: int = 500,
        debug: bool = False,
    ):
        self.iface = iface
        self.pcap_path = pcap_path
        self.buffer_window = buffer_window  # seconds
        self.write_pcap = write_pcap  # Path or None
        self.packets: List[Packet] = []
        self.sessions: List[Session] = []
        self.buffer_maxlen = buffer_maxlen
        self.debug = debug
        # Buffer: {session_key: deque of Packet}
        self._buffer = defaultdict(lambda: deque(maxlen=self.buffer_maxlen))

    def _remove_old_packets(self, current_time: float):
        """
        Remove packets from each session buffer older than buffer_window seconds.
        """
        window = self.buffer_window
        for session_key, pkt_deque in self._buffer.items():
            while pkt_deque and (current_time - pkt_deque[0].timestamp) > window:
                pkt_deque.popleft()

    def _write_pcap(self):
        """
        Write all buffered packets to a .pcap file if write_pcap is set.
        """
        if self.write_pcap is not None:
            from scapy.all import wrpcap

            all_packets = [pkt for dq in self._buffer.values() for pkt in dq]
            if all_packets:
                wrpcap(str(self.write_pcap), [pkt.data for pkt in all_packets])

    def sniff_packets(self, count: int = 0, timeout: int = None):
        """
        Sniff packets from the interface or pcap file.
        """
        if self.pcap_path:
            scapy_packets = sniff(
                offline=str(self.pcap_path), count=count, timeout=timeout
            )
        else:
            # Use promisc=True and filter out Loopback by default
            sniff_kwargs = dict(
                iface=self.iface, count=count, timeout=timeout, promisc=True
            )
            if self.iface and "loopback" in self.iface.lower():
                sniff_kwargs["promisc"] = False
            scapy_packets = sniff(**sniff_kwargs)
        self.packets = [Packet(pkt, pkt.time) for pkt in scapy_packets]
        return self.packets

    @staticmethod
    def available_interfaces():
        """
        List available network interfaces (excluding Loopback by default).
        """
        return [iface for iface in get_if_list() if "loopback" not in iface.lower()]

    def sniff_continuous(self, count: int = 0, timeout: int = None, debug: bool = None):
        """
        Continuously sniff packets, maintain a per-session buffer, and optionally write to pcap.
        If debug is True, print every captured packet using loguru.
        """
        if debug is None:
            debug = self.debug
        logger.info(f"Available interfaces: {self.available_interfaces()}")
        logger.info(f"Sniffing on interface: {self.iface}")

        def handle_packet(pkt):
            if debug:
                logger.debug(f"Captured packet: {pkt.summary()}")
            packet = Packet(pkt, pkt.time)
            ip = packet.get_layer("IP", is_scapy_layer=True)
            tcp = packet.get_layer("TCP", is_scapy_layer=True)
            udp = packet.get_layer("UDP", is_scapy_layer=True)
            proto = "TCP" if tcp else "UDP" if udp else "OTHER"
            src_port = tcp.sport if tcp else udp.sport if udp else 0
            dst_port = tcp.dport if tcp else udp.dport if udp else 0
            session_key = (
                ip.src if ip else None,
                ip.dst if ip else None,
                src_port,
                dst_port,
                proto,
            )
            self._buffer[session_key].append(packet)
            self._update_session_flow(session_key)

        sniff(
            iface=self.iface,
            prn=handle_packet,
            count=count,
            timeout=timeout,
            store=False,
            promisc=True,
        )
        logger.info("Sniffing stopped.")

    def _update_session_flow(self, session_key):
        """
        Update the SessionFlow object for the session with the given key.
        """
        packets = list(self._buffer[session_key])
        if not packets:
            return
        session = Session.from_packets(packets)
        session.session_flow = self.create_session_flow(session)
        # Optionally store or use session/session_flow as needed

    def group_sessions(self, key_func=None) -> List[Session]:
        """
        Group packets into sessions using a key function (default: 5-tuple flow).
        """
        if not self.packets:
            return []
        if key_func is None:

            def key_func(pkt: Packet):
                ip = pkt.get_layer("IP", is_scapy_layer=True)
                tcp = pkt.get_layer("TCP", is_scapy_layer=True)
                udp = pkt.get_layer("UDP", is_scapy_layer=True)
                proto = "TCP" if tcp else "UDP" if udp else "OTHER"
                src_port = tcp.sport if tcp else udp.sport if udp else 0
                dst_port = tcp.dport if tcp else udp.dport if udp else 0
                return (
                    ip.src if ip else None,
                    ip.dst if ip else None,
                    src_port,
                    dst_port,
                    proto,
                )

        from collections import defaultdict

        session_dict = defaultdict(list)
        for pkt in self.packets:
            session_dict[key_func(pkt)].append(pkt)
        self.sessions = [Session.from_packets(pkts) for pkts in session_dict.values()]
        return self.sessions

    def add_flow_features(self):
        """
        For each session, create and attach a SessionFlow object with flow-level features.
        """
        for session in self.sessions:
            session.session_flow = self.create_session_flow(session)

    def start_processing_threads(self, num_workers: int = 4):
        """
        Start background threads to process session buffers and extract features in parallel.
        """
        self._stop_event = threading.Event()
        self._threads = []
        for _ in range(num_workers):
            t = threading.Thread(target=self._session_worker, daemon=True)
            t.start()
            self._threads.append(t)
        logger.info(f"Started {num_workers} session processing threads.")

    def stop_processing_threads(self):
        """
        Signal all processing threads to stop.
        """
        if hasattr(self, "_stop_event"):
            self._stop_event.set()
            for t in getattr(self, "_threads", []):
                t.join()
            logger.info("Stopped all session processing threads.")

    def _session_worker(self):
        """
        Worker thread to process session buffers and update SessionFlow features.
        """

        while not self._stop_event.is_set():
            for session_key in list(self._buffer.keys()):
                self._update_session_flow(session_key)
            time.sleep(0.5)

    @staticmethod
    def create_session_flow(session: Session) -> SessionFlow:
        """
        Create a SessionFlow object from a Session, extracting all available features.
        Computes statistical and protocol-level features for the session.
        """
        pkts = session.packets
        if not pkts:
            return SessionFlow()
        # Extract first packet's layers for session metadata
        ip = pkts[0].get_layer("IP", is_scapy_layer=True)
        tcp = pkts[0].get_layer("TCP", is_scapy_layer=True)
        udp = pkts[0].get_layer("UDP", is_scapy_layer=True)
        proto = "TCP" if tcp else "UDP" if udp else "OTHER"
        src_port = tcp.sport if tcp else udp.sport if udp else None
        dst_port = tcp.dport if tcp else udp.dport if udp else None
        # Collect timestamps and compute inter-arrival times (IATs)
        timestamps = [p.timestamp for p in pkts]
        iats = np.diff(sorted(timestamps)) if len(timestamps) > 1 else [0]
        # Identify session direction by IP
        src_ip = ip.src if ip else None
        dst_ip = ip.dst if ip else None
        fwd_pkts = [
            p
            for p in pkts
            if p.get_layer("IP", is_scapy_layer=True)
            and p.get_layer("IP", is_scapy_layer=True).src == src_ip
        ]
        bwd_pkts = [
            p
            for p in pkts
            if p.get_layer("IP", is_scapy_layer=True)
            and p.get_layer("IP", is_scapy_layer=True).dst == src_ip
        ]
        # Compute packet lengths for forward and backward directions
        fwd_lens = [len(p.raw_bytes) for p in fwd_pkts]
        bwd_lens = [len(p.raw_bytes) for p in bwd_pkts]
        # Header lengths (total bytes in each direction)
        fwd_hdr_len = sum(len(p.raw_bytes) for p in fwd_pkts)
        bwd_hdr_len = sum(len(p.raw_bytes) for p in bwd_pkts)
        # Application/transport/data link lengths (placeholders)
        app_lens_fwd = fwd_lens
        app_lens_bwd = bwd_lens
        tr_lens_fwd = fwd_lens
        tr_lens_bwd = bwd_lens
        dl_lens_fwd = fwd_lens
        dl_lens_bwd = bwd_lens
        # Placeholder for activity/idle times
        active_times = [0]
        idle_times = [0]
        # Frame info
        frame_src = src_ip
        frame_dst = dst_ip
        # Direction and protocol-specific placeholders
        first_packet_dir = "fwd" if fwd_pkts else "bwd" if bwd_pkts else None
        most_common_req_func_code = None
        most_common_resp_func_code = None
        corrupt_config_fragments = None
        device_trouble_fragments = None
        device_restart_fragments = None
        pkts_from_master = None
        pkts_from_slave = None

        # --- Statistical feature computation ---
        total_forward_packets = len(fwd_pkts)
        total_backward_packets = len(bwd_pkts)
        total_packets_in_flow = len(pkts)
        # Forward direction statistics
        forward_dl_pkt_len_max = max(dl_lens_fwd) if dl_lens_fwd else None
        forward_dl_pkt_len_min = min(dl_lens_fwd) if dl_lens_fwd else None
        forward_dl_pkt_len_mean = mean(dl_lens_fwd) if dl_lens_fwd else None
        forward_dl_pkt_len_std = stdev(dl_lens_fwd) if len(dl_lens_fwd) > 1 else None
        # Backward direction statistics
        backward_dl_pkt_len_max = max(dl_lens_bwd) if dl_lens_bwd else None
        backward_dl_pkt_len_min = min(dl_lens_bwd) if dl_lens_bwd else None
        backward_dl_pkt_len_mean = mean(dl_lens_bwd) if dl_lens_bwd else None
        backward_dl_pkt_len_std = stdev(dl_lens_bwd) if len(dl_lens_bwd) > 1 else None
        # Transport layer statistics
        forward_transport_pkt_len_max = max(tr_lens_fwd) if tr_lens_fwd else None
        forward_transport_pkt_len_min = min(tr_lens_fwd) if tr_lens_fwd else None
        forward_transport_pkt_len_mean = mean(tr_lens_fwd) if tr_lens_fwd else None
        forward_transport_pkt_len_std = (
            stdev(tr_lens_fwd) if len(tr_lens_fwd) > 1 else None
        )
        backward_transport_pkt_len_max = max(tr_lens_bwd) if tr_lens_bwd else None
        backward_transport_pkt_len_min = min(tr_lens_bwd) if tr_lens_bwd else None
        backward_transport_pkt_len_mean = mean(tr_lens_bwd) if tr_lens_bwd else None
        backward_transport_pkt_len_std = (
            stdev(tr_lens_bwd) if len(tr_lens_bwd) > 1 else None
        )
        # Application layer statistics
        forward_app_pkt_len_max = max(app_lens_fwd) if app_lens_fwd else None
        forward_app_pkt_len_min = min(app_lens_fwd) if app_lens_fwd else None
        forward_app_pkt_len_mean = mean(app_lens_fwd) if app_lens_fwd else None
        forward_app_pkt_len_std = stdev(app_lens_fwd) if len(app_lens_fwd) > 1 else None
        backward_app_pkt_len_max = max(app_lens_bwd) if app_lens_bwd else None
        backward_app_pkt_len_min = min(app_lens_bwd) if app_lens_bwd else None
        backward_app_pkt_len_mean = mean(app_lens_bwd) if app_lens_bwd else None
        backward_app_pkt_len_std = (
            stdev(app_lens_bwd) if len(app_lens_bwd) > 1 else None
        )
        # Flow IAT statistics
        flow_iat_mean = float(np.mean(iats)) if len(iats) else None
        flow_iat_std = float(np.std(iats)) if len(iats) else None
        flow_iat_max = float(np.max(iats)) if len(iats) else None
        flow_iat_min = float(np.min(iats)) if len(iats) else None
        # Packet rates
        forward_packets_per_sec = (
            len(fwd_pkts) / session.duration if session.duration else None
        )
        backward_packets_per_sec = (
            len(bwd_pkts) / session.duration if session.duration else None
        )
        # Header lengths
        forward_dl_header_len = fwd_hdr_len
        backward_dl_header_len = bwd_hdr_len
        # Combined statistics for all directions
        dl_pkt_lens = dl_lens_fwd + dl_lens_bwd
        dl_pkt_len_mean = mean(dl_pkt_lens) if dl_pkt_lens else None
        dl_pkt_len_min = min(dl_pkt_lens) if dl_pkt_lens else None
        dl_pkt_len_max = max(dl_pkt_lens) if dl_pkt_lens else None
        dl_pkt_len_std = stdev(dl_pkt_lens) if len(dl_pkt_lens) > 1 else None
        dl_pkt_len_var = variance(dl_pkt_lens) if len(dl_pkt_lens) > 1 else None
        transport_pkt_lens = tr_lens_fwd + tr_lens_bwd
        transport_pkt_len_mean = (
            mean(transport_pkt_lens) if transport_pkt_lens else None
        )
        transport_pkt_len_min = min(transport_pkt_lens) if transport_pkt_lens else None
        transport_pkt_len_max = max(transport_pkt_lens) if transport_pkt_lens else None
        transport_pkt_len_std = (
            stdev(transport_pkt_lens) if len(transport_pkt_lens) > 1 else None
        )
        transport_pkt_len_var = (
            variance(transport_pkt_lens) if len(transport_pkt_lens) > 1 else None
        )
        app_pkt_lens = app_lens_fwd + app_lens_bwd
        app_pkt_len_mean = mean(app_pkt_lens) if app_pkt_lens else None
        app_pkt_len_min = min(app_pkt_lens) if app_pkt_lens else None
        app_pkt_len_max = max(app_pkt_lens) if app_pkt_lens else None
        app_pkt_len_std = stdev(app_pkt_lens) if len(app_pkt_lens) > 1 else None
        app_pkt_len_var = variance(app_pkt_lens) if len(app_pkt_lens) > 1 else None
        # Activity/idle statistics
        active_mean = mean(active_times) if active_times else None
        active_std = stdev(active_times) if len(active_times) > 1 else None
        active_max = max(active_times) if active_times else None
        active_min = min(active_times) if active_times else None
        idle_mean = mean(idle_times) if idle_times else None
        idle_std = stdev(idle_times) if len(idle_times) > 1 else None
        idle_max = max(idle_times) if idle_times else None
        idle_min = min(idle_times) if idle_times else None

        return SessionFlow(
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=src_port,
            destination_port=dst_port,
            protocol=proto,
            date=str(session.start_time),
            duration=session.duration,
            total_forward_packets=total_forward_packets,
            total_backward_packets=total_backward_packets,
            total_packets_in_flow=total_packets_in_flow,
            forward_dl_pkt_len_max=forward_dl_pkt_len_max,
            forward_dl_pkt_len_min=forward_dl_pkt_len_min,
            forward_dl_pkt_len_mean=forward_dl_pkt_len_mean,
            forward_dl_pkt_len_std=forward_dl_pkt_len_std,
            backward_dl_pkt_len_max=backward_dl_pkt_len_max,
            backward_dl_pkt_len_min=backward_dl_pkt_len_min,
            backward_dl_pkt_len_mean=backward_dl_pkt_len_mean,
            backward_dl_pkt_len_std=backward_dl_pkt_len_std,
            forward_transport_pkt_len_max=forward_transport_pkt_len_max,
            forward_transport_pkt_len_min=forward_transport_pkt_len_min,
            forward_transport_pkt_len_mean=forward_transport_pkt_len_mean,
            forward_transport_pkt_len_std=forward_transport_pkt_len_std,
            backward_transport_pkt_len_max=backward_transport_pkt_len_max,
            backward_transport_pkt_len_min=backward_transport_pkt_len_min,
            backward_transport_pkt_len_mean=backward_transport_pkt_len_mean,
            backward_transport_pkt_len_std=backward_transport_pkt_len_std,
            forward_app_pkt_len_max=forward_app_pkt_len_max,
            forward_app_pkt_len_min=forward_app_pkt_len_min,
            forward_app_pkt_len_mean=forward_app_pkt_len_mean,
            forward_app_pkt_len_std=forward_app_pkt_len_std,
            backward_app_pkt_len_max=backward_app_pkt_len_max,
            backward_app_pkt_len_min=backward_app_pkt_len_min,
            backward_app_pkt_len_mean=backward_app_pkt_len_mean,
            backward_app_pkt_len_std=backward_app_pkt_len_std,
            flow_iat_mean=flow_iat_mean,
            flow_iat_std=flow_iat_std,
            flow_iat_max=flow_iat_max,
            flow_iat_min=flow_iat_min,
            forward_packets_per_sec=forward_packets_per_sec,
            backward_packets_per_sec=backward_packets_per_sec,
            forward_dl_header_len=forward_dl_header_len,
            backward_dl_header_len=backward_dl_header_len,
            dl_pkt_len_mean=dl_pkt_len_mean,
            dl_pkt_len_min=dl_pkt_len_min,
            dl_pkt_len_max=dl_pkt_len_max,
            dl_pkt_len_std=dl_pkt_len_std,
            dl_pkt_len_var=dl_pkt_len_var,
            transport_pkt_len_mean=transport_pkt_len_mean,
            transport_pkt_len_min=transport_pkt_len_min,
            transport_pkt_len_max=transport_pkt_len_max,
            transport_pkt_len_std=transport_pkt_len_std,
            transport_pkt_len_var=transport_pkt_len_var,
            app_pkt_len_mean=app_pkt_len_mean,
            app_pkt_len_min=app_pkt_len_min,
            app_pkt_len_max=app_pkt_len_max,
            app_pkt_len_std=app_pkt_len_std,
            app_pkt_len_var=app_pkt_len_var,
            active_mean=active_mean,
            active_std=active_std,
            active_max=active_max,
            active_min=active_min,
            idle_mean=idle_mean,
            idle_std=idle_std,
            idle_max=idle_max,
            idle_min=idle_min,
            frame_src=frame_src,
            frame_dst=frame_dst,
            first_packet_dir=first_packet_dir,
            most_common_req_func_code=most_common_req_func_code,
            most_common_resp_func_code=most_common_resp_func_code,
            corrupt_config_fragments=corrupt_config_fragments,
            device_trouble_fragments=device_trouble_fragments,
            device_restart_fragments=device_restart_fragments,
            pkts_from_master=pkts_from_master,
            pkts_from_slave=pkts_from_slave,
            label=session.label,
        )
