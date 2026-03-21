"""
Example: Use SessionSniffer with both pcap file and live interface

This script demonstrates how to use SessionSniffer to extract session flow features
from a pcap file or a live network interface. It prints out the features for each session
and saves session images to the temp folder as soon as sessions are found.
"""

import subprocess
import threading
import time
from pathlib import Path

import cv2
from loguru import logger

from sfe.core.session.session import Session
from sfe.data.sniffer import SessionSniffer
from sfe.vis.plot import subplot_images

try:
    from scapy.arch.windows import get_windows_if_list
except ImportError:

    def get_windows_if_list():
        return []


# Set to your test pcap file path
PCAP_PATH = Path("assets/sample_pcaps/DNP3_Cold_Restart.pcap")
TEMP_DIR = Path("temp/session_images/sniffed")
TEMP_DIR.mkdir(parents=True, exist_ok=True)


def process_pcap_file():
    """
    Process a pcap file using SessionSniffer, print features, and save session images.
    """
    logger.info("Processing pcap file: {}", PCAP_PATH)
    sniffer = SessionSniffer(pcap_path=PCAP_PATH)
    packets = sniffer.sniff_packets()
    logger.info(f"Total packets sniffed: {len(packets)}")
    sessions = sniffer.group_sessions()
    logger.info(f"Total sessions found: {len(sessions)}")
    for idx, session in enumerate(sessions):
        session_flow = sniffer.create_session_flow(session)
        logger.info(f"Session {idx + 1} flow features:\n{session_flow}")
        # Save session image using cv2 (as in session_packet.py)
        try:
            arr = session.array
            if arr is not None:
                cv2.imwrite(str(TEMP_DIR / f"session_{idx + 1}.png"), arr)
        except Exception as e:
            logger.warning(f"Could not save image for session {idx + 1}: {e}")


def process_live_interface(
    iface=None, count=10, session_timeout=10, sniffer_timeout=None, debug=False
):
    """
    Process live packets from a network interface, print features, and save session images.
    """
    if iface is None:
        logger.warning("No interface specified. Skipping live sniff.")
        return
    logger.info(f"Processing live interface: {iface}")
    sniffer = SessionSniffer(iface=iface, buffer_window=session_timeout, debug=debug)
    logger.info(
        f"SessionSniffer initialized with iface={iface}, buffer_window={session_timeout}, debug={debug}"
    )
    try:
        logger.info("Sniffing packets... Press Ctrl+C to stop.")
        # Generate some traffic using curl to google.com

        def run_curl_loop():

            end_time = time.time() + (sniffer_timeout or 10)
            while time.time() < end_time:
                try:
                    logger.debug("Running curl to generate traffic...")
                    subprocess.run(
                        ["curl", "https://www.google.com"],
                        timeout=10,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                except Exception as e:
                    logger.warning(f"curl failed: {e}")
                time.sleep(2)

        curl_thread = threading.Thread(target=run_curl_loop, daemon=True)
        curl_thread.start()
        logger.info(
            f"Starting sniff_continuous on iface={iface} with count={count}, timeout={sniffer_timeout}, debug={debug}"
        )
        sniffer.sniff_continuous(count=count, timeout=sniffer_timeout, debug=debug)
        curl_thread.join(timeout=(sniffer_timeout or 10) + 5)
    except KeyboardInterrupt:
        logger.info("Sniffing stopped by user.")
    # After stopping, print session stats and save images
    logger.info(f"Buffer keys after sniffing: {list(sniffer._buffer.keys())}")
    sessions = []
    for session_key in sniffer._buffer:
        packets = list(sniffer._buffer[session_key])
        logger.info(f"Session key: {session_key}, packets in buffer: {len(packets)}")
        if packets:
            session = Session.from_packets(packets)
            session_flow = sniffer.create_session_flow(session)
            logger.info(f"Session {session_key} flow features:\n{session_flow}")
            sessions.append(session)
            arr = session.array
            header_arrs = session.header_arrays

            cv2.imwrite(str(TEMP_DIR / f"session_{session_key}.png"), arr)

            header_images = []
            header_titles = []
            for layer_name, header_arr in header_arrs.items():
                header_images.append(header_arr)
                header_titles.append(layer_name)
            subplot_images(
                header_images,
                header_titles,
                order=(1, -1),
                fig_size=(10, 10),
                ret_fig=True,
            ).savefig(TEMP_DIR / f"session_{session_key}_header_arrays.png")

            logger.info(f"Saved image for session {session_key}")
    logger.info(f"Total sessions found: {len(sessions)}")


def main():
    """
    Run both pcap and live interface processing for SessionSniffer.
    """
    # process_pcap_file()
    interface_list = SessionSniffer.available_interfaces()
    # Map GUIDs to friendly names using get_windows_if_list
    try:
        win_ifaces = get_windows_if_list()
        guid_to_name = {
            iface["guid"]: iface["description"]
            for iface in win_ifaces
            if "guid" in iface and "description" in iface
        }
    except Exception:
        guid_to_name = {}
    logger.info("Available interfaces:")
    filtered = []
    for idx, iface in enumerate(interface_list):
        guid = None
        if iface.startswith("\\Device\\NPF_"):
            guid = iface.split("NPF_")[-1].strip("{}")
        friendly = guid_to_name.get(guid, "")
        logger.info(f"  [{idx}] {iface}  |  {friendly}")
        if any(x in friendly.lower() for x in ["ethernet", "wi-fi", "wifi"]):
            filtered.append(iface)
    if not filtered:
        logger.warning("No Ethernet or Wi-Fi interfaces found. Testing all.")
        filtered = interface_list
    logger.info("Testing filtered interfaces in sequence. Press Ctrl+C to stop.")
    for iface in filtered:
        logger.info(f"Testing interface: {iface}")
        try:
            process_live_interface(
                iface=iface,
                count=10,
                session_timeout=10,
                sniffer_timeout=10,
                debug=True,
            )
        except Exception as e:
            import traceback

            traceback.print_exc()
            logger.error(f"Error testing interface {iface}: {e}")
    # To test only the 4th interface (index 3), uncomment below:
    # if len(interface_list) >= 4:
    #     logger.info(f"Testing interface 4: {interface_list[3]}")
    #     process_live_interface(iface=interface_list[3], count=10, session_timeout=10, sniffer_timeout=20, debug=True)
    # else:
    #     logger.warning("Less than 4 interfaces found. Please check your adapters.")


if __name__ == "__main__":
    main()
