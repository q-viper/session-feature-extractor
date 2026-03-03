from dataclasses import dataclass
import numpy as np
import pandas as pd
from sfe.core.packet import Packet


@dataclass
class Session:
    index: int
    start_time: pd.Timestamp
    end_time: pd.Timestamp
    packets: list[Packet]
    interval: float
    raw_bytes: list[bytearray]
    filename: str | None = None
    array: np.ndarray = None
    label: str = "NORMAL"
    _layer_arrays: np.ndarray | None = None

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
    def layer_arrays(self) -> list[dict[str, np.ndarray]]:
        if self._layer_arrays is None:
            layer_array = dict()
            max_lens = dict()
            for pkt in self.packets:
                for layer in pkt.layers:
                    if layer.name not in layer_array:
                        layer_array[layer.name] = []
                    arr = layer.array
                    max_lens[layer.name] = max(
                        max_lens.get(layer.name, 0), arr.shape[0]
                    )
                    layer_array[layer.name].append(arr)
            session_layer_arrays = {
                layer.name: np.zeros(
                    (len(self.packets), max_lens[layer.name]), dtype=np.uint8
                )
                for layer in pkt.layers
            }
            for layer_name, arrs in layer_array.items():
                session_layer_arrays[layer_name][:, : arrs[0].shape[0]] = np.stack(
                    arrs, axis=0
                )
            self._layer_arrays = session_layer_arrays

        return self._layer_arrays

    @property
    def layer_header_arrays(self) -> list[dict[str, np.ndarray]]:
        header_arrays = dict()
        for pkt in self.packets:
            if not pkt.header_arrays:
                pkt.arrays  # Force computation of arrays it will also compute header arrays
            for layer in pkt.layers:
                if layer.name not in header_arrays:
                    header_arrays[layer.name] = []
                arr = layer.header_array
                if arr is not None:
                    header_arrays[layer.name].append(arr)
        session_header_arrays = {
            layer_name: np.zeros(
                (len(self.packets), max(arr.shape[0] for arr in arrs)),
                dtype=np.uint8,
            )
            for layer_name, arrs in header_arrays.items()
        }
        for layer_name, arrs in header_arrays.items():
            session_header_arrays[layer_name][:, : arrs[0].shape[0]] = np.stack(
                arrs, axis=0
            )
        return session_header_arrays

    @property
    def session_array(self) -> np.ndarray:
        if self.array is None:
            self.array = np.zeros(
                (len(self.packets), max(pkt.array.shape[0] for pkt in self.packets)),
                dtype=np.uint8,
            )
            for i, pkt in enumerate(self.packets):
                self.array[i, : pkt.array.shape[0]] = pkt.array
        return self.array
