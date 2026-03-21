import unittest
from pathlib import Path

import numpy as np

from sfe.core.packet import Packet
from sfe.core.packet.streamer import PacketStreamer


class TestPacket(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        pcap_path = Path("assets/sample_pcaps/http_dvwa_clearlogin.pcapng")
        streamer = PacketStreamer(pcap_path)
        cls.packets = [p[0] for p in streamer]
        cls.sample_packet = cls.packets[0]  # A TCP packet

    def test_packet_creation(self):
        self.assertIsInstance(self.sample_packet, Packet)
        self.assertIsNotNone(self.sample_packet.data)
        self.assertGreater(self.sample_packet.timestamp, 0)

    def test_dissect_layers(self):
        self.assertIsNotNone(self.sample_packet._layers)
        self.assertEqual(self.sample_packet._layers.name, "Ethernet")

    def test_layers_property(self):
        layers = self.sample_packet.layers
        self.assertIsInstance(layers, list)
        self.assertGreater(len(layers), 0)
        self.assertEqual(layers[0].name, "Ethernet")
        self.assertEqual(layers[1].name, "IP")
        self.assertEqual(layers[2].name, "TCP")

    def test_layer_names_property(self):
        layer_names = self.sample_packet.layer_names
        self.assertIsInstance(layer_names, list)
        self.assertIn("Ethernet", layer_names)
        self.assertIn("IP", layer_names)
        self.assertIn("TCP", layer_names)

    def test_get_layer(self):
        ip_layer = self.sample_packet.get_layer("IP")
        self.assertIsNotNone(ip_layer)
        self.assertEqual(ip_layer.name, "IP")

        non_existent_layer = self.sample_packet.get_layer("NonExistent")
        self.assertIsNone(non_existent_layer)

    def test_raw_bytes_and_array_properties(self):
        raw_bytes = self.sample_packet.raw_bytes
        array = self.sample_packet.array
        self.assertIsInstance(raw_bytes, bytes)
        self.assertIsInstance(array, np.ndarray)
        self.assertEqual(len(raw_bytes), len(array))
        self.assertTrue(np.array_equal(np.frombuffer(raw_bytes, dtype=np.uint8), array))

    def test_layer_and_header_arrays(self):
        layer_arrays = self.sample_packet.arrays
        header_arrays = self.sample_packet.header_arrays

        self.assertIsInstance(layer_arrays, dict)
        self.assertIsInstance(header_arrays, dict)
        self.assertEqual(layer_arrays.keys(), header_arrays.keys())

        # Check that header is smaller than or equal to layer array
        for name in layer_arrays:
            self.assertLessEqual(header_arrays[name].size, layer_arrays[name].size)

        # Test concatenation
        concatenated_headers = np.concatenate(
            [header_arrays[name] for name in self.sample_packet.layer_names]
        )
        self.assertTrue(np.array_equal(concatenated_headers, self.sample_packet.array))

    def test_anonymize(self):
        anonymized_packet = self.sample_packet.anonymize()
        self.assertIsInstance(anonymized_packet, Packet)

        # Check IP anonymization
        original_ip = self.sample_packet.get_layer("IP").original
        anonymized_ip = anonymized_packet.get_layer("IP").original
        self.assertNotEqual(original_ip.src, anonymized_ip.src)
        self.assertEqual(anonymized_ip.src, "0.0.0.0")
        self.assertEqual(anonymized_ip.dst, "0.0.0.0")

        # Check TCP anonymization
        original_tcp = self.sample_packet.get_layer("TCP").original
        anonymized_tcp = anonymized_packet.get_layer("TCP").original
        self.assertNotEqual(original_tcp.sport, anonymized_tcp.sport)
        self.assertEqual(anonymized_tcp.sport, 0)
        self.assertEqual(anonymized_tcp.dport, 0)

    def test_packet_reconstruction_from_bytes(self):
        original_bytes = self.sample_packet.raw_bytes
        outer_layer_class = self.sample_packet.data.__class__

        reconstructed_packet = Packet.from_bytes(original_bytes, outer_layer_class)

        self.assertIsInstance(reconstructed_packet, Packet)
        self.assertEqual(original_bytes, reconstructed_packet.raw_bytes)
        self.assertEqual(
            self.sample_packet.layer_names, reconstructed_packet.layer_names
        )
        self.assertEqual(self.sample_packet.summary(), reconstructed_packet.summary())


if __name__ == "__main__":
    unittest.main()
