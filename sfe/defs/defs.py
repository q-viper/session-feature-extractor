"""
sfe.defs.defs
-------------

Definitions for column mapping and image type enums used in session feature extraction.
"""

from dataclasses import dataclass
from enum import Enum


@dataclass
class ColumnMapping:
    """
    Maps CSV column names to standard field names for session extraction.
    """

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
        """
        Allow setting any attribute, even if it doesn't exist.
        """
        # Allow setting any attribute, even if it doesn't exist
        object.__setattr__(self, name, value)


class NormalImageType(int, Enum):
    """
    Enum for different types of image normalization used in session visualization.
    """

    ORIGINAL = 0
    FILTERED = 1
    NORMALIZED = 2
    FILTERED_GRAM = 3
    NORMALIZED_GRAM = 4
    ZSCORE = 5
    ZGRAM1D = 6
    ZGRAM3D = 7
    UNFILTERED_GRAM = 8
    UNFILTERED_GRAM3D = 9
    FILTERED_GRAM3D = 10
