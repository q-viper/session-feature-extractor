import unittest
from pathlib import Path

import numpy as np

from sfe.core.packet.streamer import PacketStreamer
from sfe.core.session import Session


class TestSession(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        pcap_path = Path("assets/sample_pcaps/http_dvwa_clearlogin.pcapng")
        streamer = PacketStreamer(pcap_path)
        cls.packets = [p[0] for p in streamer]
        cls.session = Session.from_packets(cls.packets)

    def test_session_creation_from_packets(self):
        self.assertIsInstance(self.session, Session)
        self.assertEqual(self.session.num_packets, len(self.packets))
        self.assertGreater(self.session.duration, 0.0)

    def test_session_array(self):
        session_array = self.session.array
        self.assertIsInstance(session_array, np.ndarray)
        self.assertEqual(session_array.shape[0], self.session.num_packets)
        # Check that max length is correct
        max_pkt_len = max(len(p.raw_bytes) for p in self.packets)
        self.assertEqual(session_array.shape[1], max_pkt_len)

    def test_session_layer_arrays(self):
        layer_arrays = self.session.layer_arrays
        self.assertIsInstance(layer_arrays, dict)
        self.assertIn("IP", layer_arrays)
        self.assertEqual(layer_arrays["IP"].shape[0], self.session.num_packets)

    def test_session_header_arrays(self):
        header_arrays = self.session.header_arrays
        self.assertIsInstance(header_arrays, dict)
        self.assertIn("TCP", header_arrays)
        self.assertEqual(header_arrays["TCP"].shape[0], self.session.num_packets)

        # Header size should be <= layer size
        layer_arrays = self.session.layer_arrays
        for name in header_arrays:
            self.assertLessEqual(
                header_arrays[name].shape[1], layer_arrays[name].shape[1]
            )

    def test_session_reconstruction_from_array(self):
        session_array = self.session.array
        original_lengths = [len(p.raw_bytes) for p in self.session.packets]
        outer_layer_class = self.session.packets[0].data.__class__

        reconstructed_session = Session.from_array(
            session_array, outer_layer_class, original_lengths
        )

        self.assertIsInstance(reconstructed_session, Session)
        self.assertEqual(self.session.num_packets, reconstructed_session.num_packets)

        # Compare a few packets
        for i in [0, 10, -1]:
            original_packet = self.session.packets[i]
            reconstructed_packet = reconstructed_session.packets[i]
            self.assertEqual(original_packet.raw_bytes, reconstructed_packet.raw_bytes)
            self.assertEqual(original_packet.summary(), reconstructed_packet.summary())

    def test_from_array_no_lengths(self):
        # This tests the fallback mechanism when original_lengths is not provided
        session_array = self.session.array
        outer_layer_class = self.session.packets[0].data.__class__

        reconstructed_session = Session.from_array(session_array, outer_layer_class)
        # This reconstruction is lossy due to padding, so we can't do a perfect comparison.
        # We can, however, check that it produced the right number of packets.
        self.assertEqual(self.session.num_packets, reconstructed_session.num_packets)
        # And that the first packet seems reasonable
        self.assertGreater(len(reconstructed_session.packets[0].raw_bytes), 0)


if __name__ == "__main__":
    unittest.main()
