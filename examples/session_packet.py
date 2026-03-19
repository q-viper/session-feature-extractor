"""
examples.session_packet
----------------------

Demonstration script for session and packet extraction, array/image generation, and reconstruction.
"""

from pathlib import Path

import cv2
import numpy as np

from sfe.core.packet import Packet
from sfe.core.packet.streamer import PacketStreamer
from sfe.core.session import Session
from sfe.vis.plot import subplot_images


def main():
    """
    Run the session/packet extraction and reconstruction demo.
    """

    pcap_pth = Path("../assets/sample_pcaps/http_dvwa_clearlogin.pcapng")
    out_pth = Path("../temp")

    streamer = PacketStreamer(pcap_pth)
    packets = list(streamer)

    session = Session.from_packets([p[0] for p in packets])
    arr = session.array
    layer_arrs = session.layer_arrays
    header_arrs = session.header_arrays
    # # merge layer_arrs
    merged_arr = np.concatenate(list(header_arrs.values()), axis=-1)

    print("Merged arr shape:", merged_arr.shape, "Session arr shape:", arr.shape)
    layer_names = session.all_layer_names

    # Robust header extraction: header = layer - payload (for all but innermost)
    new_header_arrs = {}
    for i, layer_name in enumerate(layer_names):
        curr_arr = layer_arrs[layer_name]
        if i < len(layer_names) - 1:
            payload_name = layer_names[i + 1]
            payload_arr = layer_arrs[payload_name]
            # Header is the part of curr_arr not in payload_arr
            header_width = curr_arr.shape[1] - payload_arr.shape[1]
            header_array = curr_arr[:, :header_width]
        else:
            header_array = curr_arr
        new_header_arrs[layer_name] = header_array

    new_merged_arr = np.concatenate(list(new_header_arrs.values()), axis=-1)
    # assert np.array_equal(arr, new_merged_arr)

    # --- Packet Reconstruction Example ---
    # Select a single packet from the session to reconstruct (e.g., the first one)
    packet_index_to_reconstruct = 0
    original_packet = session.packets[packet_index_to_reconstruct]
    outer_layer_class = original_packet.data.__class__

    # Reconstruct from raw bytes
    reconstructed_from_bytes = Packet.from_bytes(
        original_packet.raw_bytes, outer_layer_class
    )
    assert original_packet.raw_bytes == reconstructed_from_bytes.raw_bytes
    print("✅ Reconstruction from raw bytes successful.")

    # --- Session Reconstruction from Array Example ---
    # Get the session array and original packet lengths
    session_array = session.array
    original_lengths = [len(p.raw_bytes) for p in session.packets]

    # Reconstruct the session from the array
    reconstructed_session = Session.from_array(
        session_array, outer_layer_class, original_lengths
    )

    # --- Verification of Session Reconstruction ---
    print("\n--- Session Reconstruction Verification ---")
    assert len(session.packets) == len(reconstructed_session.packets)
    print(f"Original session had {len(session.packets)} packets.")
    print(f"Reconstructed session has {len(reconstructed_session.packets)} packets.")

    # Compare a packet from the original and reconstructed sessions
    original_packet_to_compare = session.packets[10]
    reconstructed_packet_to_compare = reconstructed_session.packets[10]

    print("\nOriginal Packet Summary (from original session):")
    original_packet_to_compare.summary()
    print("\nReconstructed Packet Summary (from reconstructed session):")
    reconstructed_packet_to_compare.summary()

    assert (
        original_packet_to_compare.raw_bytes
        == reconstructed_packet_to_compare.raw_bytes
    )
    print(
        "\n✅ Verification successful: Packets from original and reconstructed sessions match."
    )
    # --- End of Reconstruction Example ---

    cv2.imwrite(str(out_pth / "session_array.png"), arr)

    layer_images = []
    layer_titles = []
    header_images = []
    header_titles = []
    for layer_name, header_arr in header_arrs.items():
        header_images.append(header_arr)
        header_titles.append(layer_name)
        layer_images.append(layer_arrs[layer_name])
        layer_titles.append(layer_name)

    subplot_images(
        layer_images, layer_titles, order=(-1, 1), fig_size=(10, 3), ret_fig=True
    ).savefig(out_pth / "session_layer_arrays.png")
    subplot_images(
        header_images, header_titles, order=(1, -1), fig_size=(10, 10), ret_fig=True
    ).savefig(out_pth / "session_header_arrays.png")


if __name__ == "__main__":
    main()
