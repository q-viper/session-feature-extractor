# Configuration

## Mapping & Column Configuration

- Place a `mapping.json` in your PCAP/CSV directory to map PCAP filenames to CSV label files.
- The extractor dynamically reads CSV columns and applies them to the `ColumnMapping` dataclass for flexible workflows.

## Directory Structure

- `sfe/core/packet/packet.py` – Packet class, array/header extraction, reconstruction
- `sfe/core/session/session.py` – Session class, aggregation, from_array
- `sfe/data/extractor.py` – Main extraction pipeline, batch processing
- `examples/extraction.py` – CLI entry point for batch extraction
- `examples/session_packet.py` – Demo: extraction, array/image generation, reconstruction
- `assets/sample_pcaps/` – Sample PCAP/CSV pairs and mapping.json
- `assets/sample_images/` – Example output images
- `temp/my_output/` – Output images, arrays, and CSVs
