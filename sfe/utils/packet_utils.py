from scapy.all import Ether, IP, TCP, Packet
import numpy as np


def anonymize_packet(packet: Packet) -> Packet:
    """Anonymize packet by removing address information"""
    # Create copy to avoid modifying original packet
    pkt = packet.copy()

    # IP layer handling
    if pkt.haslayer(IP):
        pkt[IP].src = "0.0.0.0"
        pkt[IP].dst = "0.0.0.0"

    # Ethernet layer handling
    if pkt.haslayer(Ether):
        pkt[Ether].src = "00:00:00:00:00:00"
        pkt[Ether].dst = "00:00:00:00:00:00"

    # TCP layer handling
    if pkt.haslayer(TCP):
        pkt[TCP].sport = 0
        pkt[TCP].dport = 0

    return pkt


def layers_to_uint8(layers: dict[str, Packet]) -> dict[str, np.ndarray]:
    """
    Takes a dict {layer_name: scapy_layer} and returns
    {layer_name: np.ndarray(dtype=uint8)} where each array is
    the raw bytes of that layer only.
    """
    arrs = {}
    for name, layer in layers.items():
        # bytes(layer) gives the serialized bytes of that layer (and its payload);
        # if you want strictly the header bytes, slice with layer.__len__() etc.
        raw = bytes(layer)
        arrs[name] = np.frombuffer(raw, dtype=np.uint8)
    return arrs


def get_each_layer(packet: Packet):
    """Extracts and returns a list of layers from a given packet."""
    layers = dict()
    current_layer = packet
    layer_order = []
    while current_layer:
        layers[current_layer.name] = current_layer
        layer_order.append(current_layer.name)
        if hasattr(current_layer, "payload"):
            current_layer = current_layer.payload
        else:
            break
    return layers, layer_order


def session_to_layer_arrays(parsed_session: list[Packet]):
    layer_dicts = []
    max_len = 0
    layer_names = set()
    layer_order = []
    for parsed_pkt in parsed_session:
        layers, layer_order = get_each_layer(parsed_pkt)
        layer_ints = layers_to_uint8(layers)
        layer_dicts.append(layer_ints)
        max_len = max(max_len, *[arr.shape[0] for arr in layer_ints.values()])
        layer_names.update(layer_order)
    # layer arrays
    layers = layer_dicts[0].keys()
    # reverse
    layers = list(layers)[::-1]
    layer_arrays = {
        layer: np.zeros((len(layer_dicts), max_len), dtype=np.uint8) for layer in layers
    }
    prev_arr = None
    for i, layer_dict in enumerate(layer_dicts):
        for layer, arr in layer_dict.items():
            if prev_arr is None:
                prev_arr = arr
            else:
                rev_arr = arr[::-1]
                rev_arr = rev_arr[len(prev_arr) :]
                arr = rev_arr[::-1]

            layer_arrays[layer][i, : arr.shape[0]] = arr
    layer_arrays["layer_order"] = layer_order
    return layer_arrays
