"""
sfe.defs.session_flow
--------------------

Definition for SessionFlow dataclass to store flow-level features for a session.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class SessionFlow:
    # Network flow identifiers
    source_ip: Optional[str] = None  # Source IP address
    destination_ip: Optional[str] = None  # Destination IP address
    source_port: Optional[int] = None  # Source port
    destination_port: Optional[int] = None  # Destination port
    protocol: Optional[str] = None  # Protocol (TCP/UDP/etc)
    date: Optional[str] = None  # Session start date/time
    duration: Optional[float] = None  # Session duration (seconds)

    # Packet counts
    total_forward_packets: Optional[int] = None  # Total forward packets
    total_backward_packets: Optional[int] = None  # Total backward packets
    total_packets_in_flow: Optional[int] = None  # Total packets in flow

    # Data length features
    total_forward_dl_bytes: Optional[int] = None  # Total forward data link bytes
    total_forward_transport_bytes: Optional[int] = None  # Total forward transport bytes
    total_forward_app_bytes: Optional[int] = None  # Total forward application bytes
    total_backward_dl_bytes: Optional[int] = None  # Total backward data link bytes
    total_backward_transport_bytes: Optional[int] = (
        None  # Total backward transport bytes
    )
    total_backward_app_bytes: Optional[int] = None  # Total backward application bytes

    # Packet length statistics (forward)
    forward_dl_pkt_len_max: Optional[float] = None  # Max DL forward packet length
    forward_dl_pkt_len_min: Optional[float] = None  # Min DL forward packet length
    forward_dl_pkt_len_mean: Optional[float] = None  # Mean DL forward packet length
    forward_dl_pkt_len_std: Optional[float] = None  # Std DL forward packet length
    forward_transport_pkt_len_max: Optional[float] = (
        None  # Max transport forward packet length
    )
    forward_transport_pkt_len_min: Optional[float] = (
        None  # Min transport forward packet length
    )
    forward_transport_pkt_len_mean: Optional[float] = (
        None  # Mean transport forward packet length
    )
    forward_transport_pkt_len_std: Optional[float] = (
        None  # Std transport forward packet length
    )
    forward_app_pkt_len_max: Optional[float] = None  # Max app forward packet length
    forward_app_pkt_len_min: Optional[float] = None  # Min app forward packet length
    forward_app_pkt_len_mean: Optional[float] = None  # Mean app forward packet length
    forward_app_pkt_len_std: Optional[float] = None  # Std app forward packet length

    # Packet length statistics (backward)
    backward_dl_pkt_len_max: Optional[float] = None  # Max DL backward packet length
    backward_dl_pkt_len_min: Optional[float] = None  # Min DL backward packet length
    backward_dl_pkt_len_mean: Optional[float] = None  # Mean DL backward packet length
    backward_dl_pkt_len_std: Optional[float] = None  # Std DL backward packet length
    backward_transport_pkt_len_max: Optional[float] = (
        None  # Max transport backward packet length
    )
    backward_transport_pkt_len_min: Optional[float] = (
        None  # Min transport backward packet length
    )
    backward_transport_pkt_len_mean: Optional[float] = (
        None  # Mean transport backward packet length
    )
    backward_transport_pkt_len_std: Optional[float] = (
        None  # Std transport backward packet length
    )
    backward_app_pkt_len_max: Optional[float] = None  # Max app backward packet length
    backward_app_pkt_len_min: Optional[float] = None  # Min app backward packet length
    backward_app_pkt_len_mean: Optional[float] = None  # Mean app backward packet length
    backward_app_pkt_len_std: Optional[float] = None  # Std app backward packet length

    # Flow rates
    dl_flow_bytes_per_sec: Optional[float] = None  # DL bytes/sec
    transport_flow_bytes_per_sec: Optional[float] = None  # Transport bytes/sec
    app_flow_bytes_per_sec: Optional[float] = None  # App bytes/sec
    flow_packets_per_sec: Optional[float] = None  # Packets/sec

    # Inter-arrival time (IAT) features
    flow_iat_mean: Optional[float] = None  # Mean flow IAT
    flow_iat_std: Optional[float] = None  # Std flow IAT
    flow_iat_max: Optional[float] = None  # Max flow IAT
    flow_iat_min: Optional[float] = None  # Min flow IAT
    total_forward_iat: Optional[float] = None  # Total forward IAT
    forward_iat_mean: Optional[float] = None  # Mean forward IAT
    forward_iat_std: Optional[float] = None  # Std forward IAT
    forward_iat_max: Optional[float] = None  # Max forward IAT
    forward_iat_min: Optional[float] = None  # Min forward IAT
    total_backward_iat: Optional[float] = None  # Total backward IAT
    backward_iat_mean: Optional[float] = None  # Mean backward IAT
    backward_iat_std: Optional[float] = None  # Std backward IAT
    backward_iat_max: Optional[float] = None  # Max backward IAT
    backward_iat_min: Optional[float] = None  # Min backward IAT

    # Header lengths
    forward_dl_header_len: Optional[int] = None  # Forward DL header length
    forward_transport_header_len: Optional[int] = (
        None  # Forward transport header length
    )
    forward_app_header_len: Optional[int] = None  # Forward app header length
    backward_dl_header_len: Optional[int] = None  # Backward DL header length
    backward_transport_header_len: Optional[int] = (
        None  # Backward transport header length
    )
    backward_app_header_len: Optional[int] = None  # Backward app header length

    # Packet rates
    forward_packets_per_sec: Optional[float] = None  # Forward packets/sec
    backward_packets_per_sec: Optional[float] = None  # Backward packets/sec

    # General packet length stats
    dl_pkt_len_mean: Optional[float] = None  # Mean DL packet length
    dl_pkt_len_min: Optional[float] = None  # Min DL packet length
    dl_pkt_len_max: Optional[float] = None  # Max DL packet length
    dl_pkt_len_std: Optional[float] = None  # Std DL packet length
    dl_pkt_len_var: Optional[float] = None  # Var DL packet length
    transport_pkt_len_mean: Optional[float] = None  # Mean transport packet length
    transport_pkt_len_min: Optional[float] = None  # Min transport packet length
    transport_pkt_len_max: Optional[float] = None  # Max transport packet length
    transport_pkt_len_std: Optional[float] = None  # Std transport packet length
    transport_pkt_len_var: Optional[float] = None  # Var transport packet length
    app_pkt_len_mean: Optional[float] = None  # Mean app packet length
    app_pkt_len_min: Optional[float] = None  # Min app packet length
    app_pkt_len_max: Optional[float] = None  # Max app packet length
    app_pkt_len_std: Optional[float] = None  # Std app packet length
    app_pkt_len_var: Optional[float] = None  # Var app packet length

    # Activity/idle features
    active_mean: Optional[float] = None  # Mean active time
    active_std: Optional[float] = None  # Std active time
    active_max: Optional[float] = None  # Max active time
    active_min: Optional[float] = None  # Min active time
    idle_mean: Optional[float] = None  # Mean idle time
    idle_std: Optional[float] = None  # Std idle time
    idle_max: Optional[float] = None  # Max idle time
    idle_min: Optional[float] = None  # Min idle time

    # Frame and direction
    frame_src: Optional[str] = None  # Frame source address
    frame_dst: Optional[str] = None  # Frame destination address
    first_packet_dir: Optional[str] = None  # Direction of first packet

    # Protocol-specific features
    most_common_req_func_code: Optional[str] = None  # Most common request function code
    most_common_resp_func_code: Optional[str] = (
        None  # Most common response function code
    )
    corrupt_config_fragments: Optional[int] = None  # Corrupt config fragments
    device_trouble_fragments: Optional[int] = None  # Device trouble fragments
    device_restart_fragments: Optional[int] = None  # Device restart fragments
    pkts_from_master: Optional[int] = None  # Packets from master
    pkts_from_slave: Optional[int] = None  # Packets from slave

    # Label
    label: Optional[str] = None  # Session label (e.g., attack/normal)
