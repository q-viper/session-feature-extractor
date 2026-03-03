from dataclasses import dataclass


@dataclass
class ColumnMapping:
    timestamp: str = "Timestamp"
    flow_duration: str = "Flow Duration"
    total_pkts: str = "total_pkts"
    tot_fwd_pkts: str = "Tot Fwd Pkts"
    tot_bwd_pkts: str = "Tot Bwd Pkts"
    src_ip: str = "Src IP"
    dst_ip: str = "Dst IP"
    src_port: str = "Src Port"
    dst_port: str = "Dst Port"
    protocol: str = "Protocol"
    label: str = "Label"
    flow_id: str = "Flow ID"
    flow_label: str = "Label"

    def __setattr__(self, name, value):
        # Allow setting any attribute, even if it doesn't exist
        object.__setattr__(self, name, value)
