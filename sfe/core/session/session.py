"""
sfe.core.session.session
-----------------------

Session aggregation and array/image conversion utilities for network traffic analysis.
"""

from dataclasses import dataclass

import numpy as np
import pandas as pd

from sfe.core.packet import Packet


@dataclass
class Session:
    """
    Represents a network session, aggregating packets and providing array/image conversion.
    """

    index: int
    start_time: pd.Timestamp
    end_time: pd.Timestamp
    packets: list[Packet]
    interval: float
    raw_bytes: list[bytearray]
    filename: str | None = None
    _array: np.ndarray = None
    label: str = "NORMAL"
    _layer_arrays: np.ndarray | None = None
    _header_arrays: np.ndarray | None = None
    all_layer_names: list[str] | None = None

    def __init__(
        self,
        index: int,
        start_time: pd.Timestamp,
        end_time: pd.Timestamp,
        packets: list[Packet],
        interval: float,
        raw_bytes: list[bytearray],
        filename: str | None = None,
        label: str = "NORMAL",
    ):
        """
        Initialize a Session object from a list of packets and metadata.

        Args:
            index: Session index.
            start_time: Start time of the session.
            end_time: End time of the session.
            packets: List of packets in the session.
            interval: Time interval between packets.
            raw_bytes: Raw byte data of the packets.
            filename: Optional filename associated with the session.
            label: Optional label for the session (default is "NORMAL").
        """
        self.index = index
        self.start_time = start_time
        self.end_time = end_time
        self.packets = packets
        self.interval = interval
        self.raw_bytes = raw_bytes
        self.filename = filename
        self.label = label

    @classmethod
    def from_packets(cls, packets: list[Packet], index: int = 0) -> "Session":
        """
        Create a Session from a list of Packet objects.

        Args:
            packets: List of Packet objects.
            index: Optional index for the session (default is 0).

        Returns:
            A new Session object.
        """
        if not packets:
            raise ValueError("No packets provided")

        start_time = min(pkt.timestamp for pkt in packets)
        end_time = max(pkt.timestamp for pkt in packets)
        interval = (end_time - start_time) / len(packets)

        return cls(
            index=index,
            start_time=start_time,
            end_time=end_time,
            packets=packets,
            interval=interval,
            raw_bytes=[pkt.raw for pkt in packets],
        )

    @property
    def duration(self) -> float:
        return self.end_time - self.start_time

    @property
    def num_packets(self) -> int:
        return len(self.packets)

    def __repr__(self):
        return (
            f"Session(start_time={self.start_time}, end_time={self.end_time}, "
            f"num_packets={self.num_packets}, interval={self.interval})"
        )

    @property
    def array_list(self) -> list[np.ndarray]:
        return [pkt.array for pkt in self.packets]

    @property
    def raw_bytes_list(self) -> list[bytearray]:
        return [pkt.raw for pkt in self.packets]

    @property
    def layer_arrays(self) -> dict[str, np.ndarray]:
        """
        Returns a dictionary of numpy arrays, where each key is a layer name
        and the value is a 2D array containing the padded raw data of that
        layer from all packets in the session.
        """
        if self._layer_arrays is None:
            all_layer_names = []
            max_lens = {}
            for packet in self.packets:
                for layer_name in packet.layer_names:
                    if layer_name not in all_layer_names:
                        all_layer_names.append(layer_name)
                    layer = packet.get_layer(layer_name)
                    if layer:
                        max_lens[layer_name] = max(
                            max_lens.get(layer_name, 0), len(layer.array)
                        )
            self.all_layer_names = all_layer_names

            self._layer_arrays = {
                name: np.zeros(
                    (self.num_packets, max_lens.get(name, 0)), dtype=np.uint8
                )
                for name in self.all_layer_names
            }

            for i, packet in enumerate(self.packets):
                for layer_name, layer_array in packet.arrays.items():
                    if layer_name in self._layer_arrays:
                        padded_array = np.pad(
                            layer_array,
                            (
                                0,
                                self._layer_arrays[layer_name].shape[1]
                                - len(layer_array),
                            ),
                            "constant",
                        )
                        self._layer_arrays[layer_name][i] = padded_array
        return self._layer_arrays

    @property
    def header_arrays(self) -> dict[str, np.ndarray]:
        """
        Returns a dictionary of numpy arrays for the headers of each layer across
        all packets in the session. The arrays are padded to a uniform length.
        """
        if self._header_arrays is None:
            # Ensure layer_arrays and all_layer_names are computed first
            if self.all_layer_names is None:
                _ = self.layer_arrays

            max_header_lens = {}
            for packet in self.packets:
                for layer_name, header_arr in packet.header_arrays.items():
                    if header_arr is not None:
                        max_header_lens[layer_name] = max(
                            max_header_lens.get(layer_name, 0), len(header_arr)
                        )

            self._header_arrays = {
                name: np.zeros(
                    (self.num_packets, max_header_lens.get(name, 0)), dtype=np.uint8
                )
                for name in self.all_layer_names
            }

            for i, packet in enumerate(self.packets):
                for layer_name, header_arr in packet.header_arrays.items():
                    if layer_name in self._header_arrays and header_arr is not None:
                        padded_array = np.pad(
                            header_arr,
                            (
                                0,
                                self._header_arrays[layer_name].shape[1]
                                - len(header_arr),
                            ),
                            "constant",
                        )
                        self._header_arrays[layer_name][i] = padded_array
        return self._header_arrays

    @property
    def array(self) -> np.ndarray:
        if self._array is None:
            max_len = 0
            for pkt in self.packets:
                if pkt.array is not None:
                    max_len = max(max_len, pkt.array.shape[0])

            self._array = np.zeros(
                (len(self.packets), max_len),
                dtype=np.uint8,
            )
            for i, pkt in enumerate(self.packets):
                if pkt.array is not None:
                    self._array[i, : pkt.array.shape[0]] = pkt.array
        return self._array

    @classmethod
    def from_array(
        cls,
        session_array: np.ndarray,
        outer_layer_class: type,
        original_lengths: list[int] = None,
    ) -> "Session":
        """
        Reconstruct a Session from a numpy array and metadata.

        Args:
            session_array: A 2D numpy array where each row is a packet.
            outer_layer_class: The Scapy class of the outermost layer for each packet.
            original_lengths: A list of the original, unpadded lengths of each packet.
                              If not provided, the full array row will be used.

        Returns:
            A new Session object.
        """
        packets = []
        for i, packet_row in enumerate(session_array):
            if original_lengths:
                packet_bytes = packet_row[: original_lengths[i]].tobytes()
            else:
                # Find the last non-zero byte to estimate original length
                non_zero_indices = np.where(packet_row != 0)[0]
                if len(non_zero_indices) > 0:
                    last_non_zero = non_zero_indices[-1]
                    packet_bytes = packet_row[: last_non_zero + 1].tobytes()
                else:
                    packet_bytes = b""

            if packet_bytes:
                packet = Packet.from_bytes(packet_bytes, outer_layer_class)
                packets.append(packet)

        if not packets:
            return cls(
                index=0,
                start_time=pd.Timestamp.now(),
                end_time=pd.Timestamp.now(),
                packets=[],
                interval=0,
                raw_bytes=[],
            )

        return cls.from_packets(packets)
