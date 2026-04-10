# Session Feature Extractor (sfe)

> **Requirements:**
> Python 3.10+
> [scapy](https://scapy.net/) (Python package, see pyproject.toml)
> [editcap](https://www.wireshark.org/docs/man-pages/editcap.html) (external tool, for PCAP/PCAPNG conversion)
> For HPC/cluster use: [apptainer](https://apptainer.org/) (or Singularity) is recommended for containerized workflows.

A Python package for extracting, reconstructing, and visualizing session-based features from network traffic (PCAP files). Designed for research and practical applications in network intrusion detection, traffic analysis, and machine learning.

- **Session & Packet Extraction**: Extracts sessions and packets from PCAPs, supporting TCP/IP stack and custom protocols.
- **Layer-wise Array & Header Extraction**: Converts packets/sessions into numpy arrays for each protocol layer and their headers.
- **Reconstruction**: Reconstructs packets and sessions from numpy arrays, enabling round-trip conversion.
- **Batch Processing CLI**: Powerful command-line interface for batch extraction, filtering, and output management.
- **Visualization**: Generates grayscale images from session/packet arrays for ML and visualization.
- **Flexible Mapping**: Supports dynamic column mapping from CSV label files and mapping.json.
- **Multiprocessing**: Efficient parallel processing for large datasets.
- **Logging**: Detailed logging with Loguru.
- **Unit Tests**: Robust test coverage for core extraction and reconstruction logic.

## Quick Start

See the [Examples](examples.md) page for a full demonstration and sample outputs.
