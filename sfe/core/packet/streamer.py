"""
sfe.core.packet.streamer
-----------------------

PacketStreamer for iterating over packets in a PCAP file, with support for filtering and multiprocessing.
"""

import gc
import shlex
import subprocess
import time
import traceback
from datetime import datetime, timedelta
from pathlib import Path

import psutil
from loguru import logger
from scapy.all import PcapReader, rdpcap

from sfe.core.packet.packet import Packet


class PacketStreamer:
    """
    Streams packets from a PCAP file, optionally filtering by time, IP, and port.
    Supports multiprocessing and containerized packet extraction.

    Args:
        pcap_path (Path): Path to the input PCAP file.
        name (str, optional): Name for the temporary files/session.
        temp_dir (Path, optional): Directory for temporary files.
        store_packets (bool): Whether to store all packets in memory.
        use_editcap (bool): Use editcap for splitting/filtering.
        use_tshark (bool): Use tshark for advanced filtering.
        process_id (int): Identifier for the process/session.
        use_apptainer (bool): Use apptainer container for editcap/tshark.
        container (str): Container image to use for apptainer.
        start_timestamp (float, optional): Start time for filtering.
        end_timestamp (float, optional): End time for filtering.
    """

    def __init__(
        self,
        pcap_path: Path,
        name: str | None = None,
        temp_dir: Path | None = None,
        store_packets: bool = False,
        use_tshark: bool = False,
        use_editcap: bool = True,
        process_id: int = 0,
        use_apptainer=True,
        container: str = "docker://cincan/tshark",
        start_timestamp: float | None = None,
        end_timestamp: float | None = None,
    ):
        """
        Initialize the PacketStreamer with PCAP path and filtering options.

        Args:
            pcap_path (Path): Path to the input PCAP file.
            name (str, optional): Name for the temporary files/session.
            temp_dir (Path, optional): Directory for temporary files.
            store_packets (bool): Whether to store all packets in memory.
            use_editcap (bool): Use editcap for splitting/filtering.
            use_tshark (bool): Use tshark for advanced filtering.
            process_id (int): Identifier for the process/session.
            use_apptainer (bool): Use apptainer container for editcap/tshark.
            container (str): Container image to use for apptainer.
            start_timestamp (float, optional): Start time for filtering.
            end_timestamp (float, optional): End time for filtering.
        """
        self.use_apptainer = use_apptainer
        self.container = container
        self.pcap_path = pcap_path
        self.curr_index = 0
        self.curr_packet = None
        self.curr_packet_time = None
        self.store_packets = store_packets
        self.use_tshark = use_tshark
        self.all_packets = []
        # if available, use temp dir else create temp in working dir
        self.temp_dir = temp_dir if temp_dir else Path.cwd() / "temp"
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        # if available, else random name
        self.temp_name = name if name else f"process_{process_id}"
        self.temp_path = self.temp_dir / f"{self.temp_name}_temp.pcap"
        self.process_id = process_id
        self.first_timestamp = start_timestamp
        self.end_timestamp = end_timestamp
        self.use_editcap = use_editcap

        if not self.pcap_path.exists():
            logger.error(
                f"PROCESS:{self.process_id} PCAP file not found: {self.pcap_path}"
            )
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_path}")

        if self.first_timestamp and self.end_timestamp:
            logger.info(
                f"PROCESS:{self.process_id} PacketStreamer initializing for timestamps between {self.first_timestamp} and {self.end_timestamp}"
            )
            split_path = self.temp_dir / f"{self.temp_name}_split.pcap"
            # now split the pcap to only include packets between these timestamps
            ret_code = self.split_session(
                self.first_timestamp,
                self.end_timestamp,
                initial_split=True,
                split_path=split_path,
            )
            if not ret_code:
                logger.error(
                    f"PROCESS:{self.process_id} Failed to initialize PacketStreamer with editcap splitting."
                )
                raise RuntimeError("Failed to split pcap with editcap.")
            logger.info(
                f"PROCESS:{self.process_id} Successfully initialized PacketStreamer with editcap splitting and new split file at {split_path}."
            )
            self.pcap_path = split_path

    def __iter__(self):
        """
        Generator to yield parsed packets and their timestamps from the current pcap file.
        Yields:
            tuple: (pkt, ts) where pkt is a Scapy packet and ts is the timestamp (float).
        """
        for pkt in PcapReader(str(self.pcap_path)):
            ts = pkt.time
            self.curr_index += 1
            pkt = Packet(pkt, ts)
            if self.store_packets:
                self.all_packets.append((pkt, ts))
            yield pkt, ts

    def split_session(
        self,
        start_ts: float,
        end_ts: float,
        src_ip: str | None = None,
        dst_ip: str | None = None,
        src_port: int | None = None,
        dst_port: int | None = None,
        initial_split: bool = False,
        split_path: Path | None = None,
    ):
        """
        Split packets into sessions based on start and end timestamps using editcap or Scapy fallback.
        Optionally filter by IP and port using tshark.
        Args:
            start_ts (float): Start timestamp (epoch seconds).
            end_ts (float): End timestamp (epoch seconds).
            src_ip (str, optional): Source IP to filter.
            dst_ip (str, optional): Destination IP to filter.
            src_port (int, optional): Source port to filter.
            dst_port (int, optional): Destination port to filter.
            initial_split (bool): If True, only split by time and return True/False.
            split_path (Path, optional): Path to write the split pcap.
        Returns:
            list: List of filtered packets (if not initial_split), or True/False for initial split.
        """
        if split_path is None:
            split_path = self.temp_path
        # Convert epoch to datetime
        start_dt = datetime.fromtimestamp(float(start_ts))
        end_dt = datetime.fromtimestamp(float(end_ts))

        # Add 1-second tolerance (common fix for microsecond mismatches)
        tolerance = timedelta(seconds=1)
        start_dt -= tolerance
        end_dt += tolerance

        start_formatted = start_dt.strftime("%Y-%m-%d %H:%M:%S")
        end_formatted = end_dt.strftime("%Y-%m-%d %H:%M:%S")

        logger.info(
            f"PROCESS:{self.process_id} Writing packets of window: {start_formatted} → {end_formatted}"
        )

        # Try editcap first bcz its fast
        # change split_path
        if self.use_apptainer:
            editcap_cmd = [
                "apptainer",
                "exec",
                "--no-home",
                "--cleanenv",
                self.container,
                "editcap",
                str(self.pcap_path),
                str(split_path),
                "-A",
                start_formatted,
                "-B",
                end_formatted,
            ]
        else:
            editcap_cmd = shlex.split(
                f'editcap "{self.pcap_path}" "{split_path}" -A "{start_formatted}" -B "{end_formatted}"'
            )
        filtered_packets = None
        try:
            # Execute command and wait for it to complete
            # also print full error if any
            t0 = time.time()
            process = subprocess.run(
                editcap_cmd,
                capture_output=True,  # FIXED: NO shell=True for lists
                text=True,
            )
            t1 = time.time()

            if process.returncode != 0:
                logger.error(f"EDITCAP FAILED: {process.stderr}")
                logger.error(f"EDITCAP CMD: {' '.join(map(str, editcap_cmd))}")
                raise subprocess.CalledProcessError(
                    process.returncode, editcap_cmd, process.stderr
                )

            logger.info(
                f"PROCESS:{self.process_id} Completed splitting PCAP ({start_formatted} → {end_formatted}) with editcap. Time taken: {t1 - t0:.2f} seconds"
            )
            pcap_path = self.temp_path
            if initial_split:
                return True
            # NOTE: This is clearly slower than editcap then tshark filtering
            # # now make tshark cmd that filters by src and dst ip if provided aand also implements start and end time
            # # and write the time taken to find best one
            # SRC_IP = src_ip
            # DST_IP = dst_ip
            # tshark_cmd = f"""tshark -r {str(self.pcap_path)} \
            # -Y "frame.time >= \\"{start_formatted}\\" && frame.time <= \\"{end_formatted}\\" && ((ip.src == {SRC_IP} && ip.dst == {DST_IP}) || (ip.src == {DST_IP} && ip.dst == {SRC_IP}))" \
            # -w {self.temp_path}
            # """
            # logger.info(
            #     f"PROCESS:{self.process_id} Running tshark command: {tshark_cmd}"
            # )
            # t0 = time.time()
            # tshark_process = subprocess.run(
            #     tshark_cmd, shell=True, capture_output=True, text=True
            # )
            # t1 = time.time()
            # logger.info(
            #     f"PROCESS:{self.process_id} Completed filtering PCAP with tshark. Time taken: {t1 - t0:.2f} seconds"
            # )
            # if tshark_process.returncode != 0:
            #     raise subprocess.CalledProcessError(
            #         tshark_process.returncode, tshark_cmd, tshark_process.stderr
            #     )

            # use tshark now to filter by src and dst ip if provided
            if (src_ip or dst_ip) and self.use_tshark:
                # either src==src_ip and dst==dst_ip or src==dst_ip and dst==src_ip
                # Replace with your IPs
                SRC_IP = src_ip
                DST_IP = dst_ip
                filtered_path = (
                    self.temp_path.parent / f"{self.temp_name}_filtered.pcap"
                )

                if self.use_apptainer:
                    tshark_cmd = f"""apptainer exec --no-home --cleanenv {self.container} tshark -r {str(self.temp_path)} """
                    tshark_cmd += f"""-Y "(ip.src == {SRC_IP} && ip.dst == {DST_IP}) || (ip.src == {DST_IP} && ip.dst == {SRC_IP})" """
                    if src_port is not None and dst_port is not None:
                        tshark_cmd += f"""-Y "((tcp.srcport == {src_port} && tcp.dstport == {dst_port}) || (tcp.srcport == {dst_port} && tcp.dstport == {src_port}))" """
                    tshark_cmd += f"""-w {str(filtered_path)}"""
                else:
                    tshark_cmd = f"""tshark -r {str(self.temp_path)} -Y "(ip.src == {SRC_IP} && ip.dst == {DST_IP}) || (ip.src == {DST_IP} && ip.dst == {SRC_IP})" """
                    if src_port is not None and dst_port is not None:
                        tshark_cmd += f"""-Y "((tcp.srcport == {src_port} && tcp.dstport == {dst_port}) || (tcp.srcport == {dst_port} && tcp.dstport == {src_port}))" """
                    tshark_cmd += f"""-w {filtered_path}"""
                # logger.info(
                #     f"PROCESS:{self.process_id} Running tshark command: {tshark_cmd}"
                # )
                t0 = time.time()
                tshark_process = subprocess.run(
                    tshark_cmd, capture_output=True, text=True, shell=True
                )
                t1 = time.time()
                logger.info(
                    f"PROCESS:{self.process_id} Completed filtering PCAP with tshark. Time taken: {t1 - t0:.2f} seconds"
                )
                if tshark_process.returncode != 0:
                    logger.error(f"TSHARK FAILED - stderr: {tshark_process.stderr}")
                    logger.error(f"TSHARK CMD: {' '.join(map(str, tshark_cmd))}")
                    logger.error(f"TSHARK STDOUT: {tshark_process.stdout}")
                    raise subprocess.CalledProcessError(
                        tshark_process.returncode, tshark_cmd, tshark_process.stderr
                    )
                # remove the unfiltered temp file
                self.temp_path.unlink()
                pcap_path = filtered_path

            # Read filtered packets from temp file
            # but first check the available memory to avoid crashes
            # and then assume how much memory the pcap would take and if enough, read it
            # else wait for few seconds and retry
            while True:
                gc.collect()
                mem_available = (
                    psutil.virtual_memory().available * 0.7
                )  # 70% of available memory
                pcap_size = pcap_path.stat().st_size

                if mem_available > pcap_size:
                    filtered_packets = []
                    for pkt in rdpcap(str(pcap_path)):
                        filtered_packets.append(Packet(pkt, pkt.time))
                    break
                else:
                    logger.warning(
                        f"PROCESS:{self.process_id} Not enough memory to read {self.temp_path}. Waiting..."
                    )
                    time.sleep(5)
            # remove this temp file
            pcap_path.unlink()

        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            logger.error(f"EDITCAP/TSHARK ERROR: {e}")
            logger.warning(
                f"PROCESS:{self.process_id} failed: {e}\n {traceback.format_exc()}"
            )
            logger.info(f"PROCESS:{self.process_id} Falling back to Scapy filtering")

            # Scapy fallback - filter packets by timestamp and write to temp file
            filtered_packets = []
            adjusted_start_ts = start_ts - 2.0  # Apply tolerance
            adjusted_end_ts = end_ts + 2.0

            try:
                for pkt, ts in self.__iter__():
                    if adjusted_start_ts <= ts <= adjusted_end_ts:
                        filtered_packets.append(pkt)

                return filtered_packets

            except Exception as scapy_error:
                logger.error(
                    f"PROCESS:{self.process_id} Scapy fallback failed: {scapy_error} \n {traceback.format_exc()}"
                )

            logger.info(
                f"PROCESS:{self.process_id} Completed splitting PCAP ({start_formatted} → {end_formatted}) with Scapy fallback."
            )
        return filtered_packets

    def get_packets(
        self,
        num_packets: int | None = None,
        start_ts: float | None = None,
        end_ts: float | None = None,
        src_ip: str | None = None,
        dst_ip: str | None = None,
        src_port: int | None = None,
        dst_port: int | None = None,
    ) -> list[Packet]:
        """
        Retrieve packets from the pcap file, optionally filtering by number, time, IP, and port.
        Args:
            num_packets (int, optional): Number of packets to retrieve.
            start_ts (float, optional): Start timestamp for filtering.
            end_ts (float, optional): End timestamp for filtering.
            src_ip (str, optional): Source IP to filter.
            dst_ip (str, optional): Destination IP to filter.
            src_port (int, optional): Source port to filter.
            dst_port (int, optional): Destination port to filter.
        Returns:
            list: List of (pkt, ts) tuples.
        """
        logger.info(
            f"PROCESS:{self.process_id} Retrieving packets from {self.pcap_path}"
        )
        packets = []

        if not self.use_editcap:
            if num_packets is not None:
                for _ in range(num_packets):
                    try:
                        pkt, ts = next(self.__iter__())
                        packets.append(pkt)
                    except StopIteration:
                        break
            elif start_ts is not None and end_ts is not None:
                for pkt_ts in self.__iter__():
                    pkt, ts = pkt_ts
                    if start_ts <= ts <= end_ts:
                        packets.append(pkt)
                    elif ts > end_ts:
                        break
                logger.info(
                    f"PROCESS:{self.process_id} Retrieved {len(packets)} packets from PCAP between {start_ts} and {end_ts}."
                )
        else:
            t0 = time.time()
            # Use editcap to split pcap and read packets
            all_packets = self.split_session(
                start_ts,
                end_ts,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
            )

            try:
                packets = []
                for pkt in all_packets:
                    packets.append(pkt)

                logger.info(
                    f"PROCESS:{self.process_id} Retrieved {len(packets)} packets from PCAP between {start_ts} and {end_ts} in {time.time() - t0:.2f} seconds."
                )
            except Exception as e:
                logger.error(
                    f"PROCESS:{self.process_id} Error reading temp file {self.temp_path}: {e}\n {traceback.format_exc()}"
                )
                return packets
        return packets

    def cleanup(self):
        """
        Clean up any temporary files or resources used by the streamer.
        """
        if self.temp_path.exists():
            self.temp_path.unlink()
            logger.info(
                f"PROCESS:{self.process_id} Deleted temporary file: {self.temp_path}"
            )
