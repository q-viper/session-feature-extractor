from pathlib import Path
from sfe.core.packet.streamer import PacketStreamer

pcap_pth = Path("assets/sample_pcaps/http_dvwa_clearlogin.pcapng")

streamer = PacketStreamer(pcap_pth)

for pkt, ts in streamer:
    print(pkt)
    arrays = pkt.arrays

    pass
