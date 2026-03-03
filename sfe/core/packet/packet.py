from typing import Any
import numpy as np
from scapy.all import Packet as ScapyPacket, raw
from dataclasses import dataclass, field
from sfe.utils.packet_utils import anonymize_packet


@dataclass
class Layer:
    name: str
    fields: dict = field(default_factory=dict)
    payload: "Layer" = None
    original: Any = None
    _raw: bytes | None = None
    _array: np.ndarray | None = None  # For storing uint8 array representation if needed
    _header_array: np.ndarray | None = (
        None  # For storing uint8 array of just the header if needed
    )

    @property
    def header_array(self) -> np.ndarray | None:
        return self._header_array

    @header_array.setter
    def header_array(self, value: np.ndarray):
        self._header_array = value

    @property
    def raw(self) -> bytes | None:
        if self._raw is None:
            self._raw = raw(self.original) if self.original else b""
        return self._raw

    @property
    def array(self) -> np.ndarray:
        if self._array is None:
            self._array = (
                np.frombuffer(self.raw, dtype=np.uint8)
                if self.raw
                else np.array([], dtype=np.uint8)
            )
        return self._array

    def summary(self) -> str:
        if self.original and hasattr(self.original, "summary"):
            return self.original.summary()
        return f"{self.name}: {self.fields}"

    def show(self) -> None:
        if self.original and hasattr(self.original, "show"):
            self.original.show()
        else:
            print(self.summary())

    def get_field(self, field_name):
        return self.fields.get(field_name, None)

    def __repr__(self):
        return f"Layer(name={self.name}, fields={self.fields}, payload={repr(self.payload)})"


class Packet:
    """Represents a network packet, recursively wrapping scapy layers as Layer objects."""

    def __init__(self, data: ScapyPacket | Any, timestamp: float = 0.0):
        self.data = data  # scapy packet or raw data
        self.timestamp = float(timestamp)
        self._layers: list[Layer] = self._dissect_layers(self.data)
        self._array = None  # For storing uint8 array representation if needed
        self._arrays = dict()  # For storing uint8 arrays of each layer if needed
        self._header_arrays = (
            dict()
        )  # For storing uint8 arrays of just the headers of each layer if needed

    @property
    def header_arrays(self) -> dict[str, np.ndarray]:
        if not self._header_arrays:
            self.arrays  # noqa
            for layer in self.layers:
                self._header_arrays[layer.name] = layer.header_array
        return self._header_arrays

    @property
    def arrays(self) -> dict[str, np.ndarray]:
        """Return a dict of {layer_name: uint8 array} for each layer."""
        if not self._arrays:
            for layer in self.layers:
                self._arrays[layer.name] = layer.array
            prev_arr = None
            for layer in self.layers[::-1]:
                curr_arr = layer.array
                if prev_arr is None:
                    layer.header_array = curr_arr  # For the innermost layer, header is the same as the full array
                else:
                    rev_arr = curr_arr[::-1]
                    rev_arr = rev_arr[len(prev_arr) :]
                    layer.header_array = rev_arr[::-1]
                prev_arr = curr_arr
            # ensure concat of headers and curr array is same
            assert np.array_equal(
                np.concatenate(
                    [
                        layer.header_array
                        for layer in self.layers
                        if layer.header_array is not None
                    ]
                ),
                self.array,
            )
        return self._arrays

    @property
    def array(self) -> np.ndarray:
        if self._array is None:
            self._array = (
                np.frombuffer(self.raw_bytes, dtype=np.uint8)
                if self.raw_bytes
                else np.array([], dtype=np.uint8)
            )
        return self._array

    @property
    def raw_bytes(self):
        """Return the raw bytes of the entire packet."""
        if hasattr(self.data, "raw"):
            return self.data.raw()
        elif hasattr(self.data, "__bytes__"):
            return raw(self.data)
        else:
            return b""

    @property
    def anonymize(self):
        """Return a new Packet with anonymized data."""
        if isinstance(self.data, ScapyPacket):
            anonymized_data = anonymize_packet(self.data)
            return Packet(anonymized_data, self.timestamp)
        else:
            # If it's raw data, we can't anonymize it without parsing
            return self  # or raise an exception

    @property
    def layers(self):
        """Return a list of Layer objects representing each protocol layer."""
        layers_list: list[Layer] = []
        current = self._layers
        while current:
            layers_list.append(current)
            current = current.payload
        return layers_list

    def _dissect_layers(self, scapy_layer) -> Layer:
        if scapy_layer is None:
            return None
        layer = Layer(
            name=getattr(scapy_layer, "name", type(scapy_layer).__name__),
            fields=dict(getattr(scapy_layer, "fields", {})),
            original=scapy_layer,
        )
        # Recursively wrap the payload
        payload = getattr(scapy_layer, "payload", None)
        if payload and hasattr(payload, "name") and payload.name != "NoPayload":
            layer.payload = self._dissect_layers(payload)

        return layer

    def summary(self):
        if hasattr(self.data, "summary"):
            return self.data.summary()
        return str(self.data)

    def show(self):
        if hasattr(self.data, "show"):
            self.data.show()
        else:
            print(self.data)

    @property
    def raw(self):
        if hasattr(self.data, "raw"):
            return self.data.raw()
        return raw(self.data)

    def __getattr__(self, name):
        """Delegate attribute and method access to the underlying scapy packet if not found in Packet."""
        # Avoid recursion for special attributes
        if name in self.__dict__:
            return self.__dict__[name]
        # Try to get from self.data
        data = object.__getattribute__(self, "data")
        try:
            return getattr(data, name)
        except AttributeError:
            raise AttributeError(
                f"'{type(self).__name__}' object has no attribute '{name}'"
            )

    def __dir__(self):
        # Combine Packet and self.data attributes for tab-completion
        return list(super().__dir__()) + list(dir(self.data))

    def __repr__(self):
        return f"Packet(timestamp={self.timestamp}, layers={self.layers})"
