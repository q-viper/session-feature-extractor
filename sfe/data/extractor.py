"""
sfe.data.extractor
------------------

Session feature extraction pipeline for PCAP files. Handles batch processing, multiprocessing, and feature/image extraction for network sessions.
"""

import gc
import sys
import traceback
from datetime import datetime
from pathlib import Path

import cv2
import numpy as np
import pandas as pd
from loguru import logger
from scapy.all import IP, TCP, UDP, Ether, raw, wrpcap
from tqdm import tqdm

from sfe.core.packet import Packet
from sfe.defs import ColumnMapping

from ..core.packet.streamer import PacketStreamer
from ..core.session.session import Session


class PCAPSessionFeatureExtractor:
    """
    Extracts session-based features from PCAP files, including array and image representations.

    Handles loading, filtering, and processing of network sessions, and supports saving results as images, arrays, and CSVs.
    """

    def __init__(
        self,
        process_id: int,
        out_dir: Path = Path("rosids23_labelled_sessions"),
        anynomize: bool = True,
        max_sessions: int = -1,
        correction_msec: float = 0.0,
        write_every: int = 100,
        min_labeled_pkts: int = -1,
        max_labeled_pkts: int = -1,
        adaptive_correction_msec: bool = True,
        temp_dir: Path | None = None,
        use_apptainer: bool = True,
        container: str = "docker://cincan/tshark",
        use_tshark: bool = True,
        write_image: bool = True,
        write_array: bool = True,
        column_mapping: ColumnMapping = ColumnMapping(),
        write_session_pcap: bool = False,
    ):
        """
        Initialize the session feature extractor.

        Args:
            process_id (int): Process ID for multiprocessing.
            out_dir (Path): Output directory for results.
            anynomize (bool): Whether to anonymize packets.
            max_sessions (int): Maximum number of sessions to process.
            correction_msec (float): Timestamp correction in microseconds.
            write_every (int): Save every N sessions.
            min_labeled_pkts (int): Minimum labeled packets per session.
            max_labeled_pkts (int): Maximum labeled packets per session.
            adaptive_correction_msec (bool): Adaptive timestamp correction.
            temp_dir (Path): Temporary directory.
            use_apptainer (bool): Use Apptainer for containerization.
            container (str): Container image.
            use_tshark (bool): Use Tshark for packet parsing.
            write_image (bool): Save session images.
            write_array (bool): Save session arrays.
            column_mapping (ColumnMapping): Column mapping for CSVs.
            write_session_pcap (bool): Save session PCAPs.
        """
        self.use_tshark = use_tshark
        self.container = container
        self.use_apptainer = use_apptainer
        self.packet_buffer = None
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.sessions = []
        self.stats = None
        self.anynomize = anynomize
        self.max_sessions = max_sessions
        self.correction_msec = correction_msec
        self.write_every = write_every
        self.min_labeled_pkts = min_labeled_pkts
        self.max_labeled_pkts = max_labeled_pkts
        self.adaptive_correction_msec = adaptive_correction_msec
        self.process_id = process_id
        self.temp_dir = temp_dir if temp_dir else Path.cwd() / "temp"
        self.label_df = None
        self.packet_streamer = None
        self.pcap_path = None
        self.label_file = None
        self.layer_names = set()
        self.write_image = write_image
        self.write_array = write_array
        self.column_mapping = column_mapping
        self.write_session_pcap = write_session_pcap

    def load(self, pcap_path: Path, label_df: pd.DataFrame):
        """
        Load packets from the PCAP file and prepare for session extraction.

        Args:
            pcap_path (Path): Path to the PCAP file.
            label_df (pd.DataFrame): DataFrame with session/label information.
        """
        self.pcap_path = pcap_path
        self.label_df = label_df
        logger.info(
            f"PROCESS:{self.process_id} Loading packets from {self.pcap_path}..."
        )
        start_dt = label_df[self.column_mapping.timestamp].to_list()[0]
        end_ts = (
            label_df[self.column_mapping.timestamp].to_list()[-1].timestamp() * 1e6
            + label_df[self.column_mapping.flow_duration].to_list()[-1]
            + self.correction_msec
        )
        # convert back to datetime
        end_dt = pd.to_datetime(end_ts, unit="us")
        # convert to seconds
        start_sec = start_dt.timestamp()
        end_sec = end_dt.timestamp()
        self.packet_streamer = PacketStreamer(
            self.pcap_path,
            process_id=self.process_id,
            temp_dir=self.temp_dir,
            use_apptainer=self.use_apptainer,
            container=self.container,
            start_timestamp=start_sec,
            end_timestamp=end_sec,
            use_tshark=self.use_tshark,
        )
        logger.info(
            f"PROCESS:{self.process_id} Created PacketStreamer for packet loading."
        )
        # format as yyyyMMdd_HHmm
        now = datetime.now().strftime("%Y%m%d_%H%M")
        self.label_file = (
            self.out_dir
            / f"labelled_sessions_{pcap_path.stem}_{self.process_id}_{now}.csv"
        )
        with open(self.label_file, "w") as f:  # noqa
            pass

    def packets_to_labelled_sessions(
        self,
        packet_streamer: "PacketStreamer",
        df: pd.DataFrame = pd.DataFrame(),
    ):
        """
        Match packets to labeled sessions and return session objects.

        Args:
            packet_streamer (PacketStreamer): Streamer for reading packets.
            df (pd.DataFrame): DataFrame with session/label information.
        Returns:
            list[Session]: List of session objects with matched packets.
        """
        labelled_sessions = []
        file_path = self.pcap_path

        output_path = self.out_dir

        num_rows = len(df)
        if self.min_labeled_pkts > 0:
            logger.info(
                f"PROCESS:{self.process_id} Filtering sessions with min_labeled_pkts={self.min_labeled_pkts}"
            )
            num_rows = len(df)
            df = df[df[self.column_mapping.total_pkts] >= self.min_labeled_pkts]
            logger.info(
                f"PROCESS:{self.process_id} Filtered {num_rows - len(df)} sessions"
            )
        if self.max_labeled_pkts > 0:
            df = df[df[self.column_mapping.total_pkts] <= self.max_labeled_pkts]
            logger.info(
                f"PROCESS:{self.process_id} Filtered {num_rows - len(df)} sessions"
            )

        if self.adaptive_correction_msec:
            logger.warning(
                f"PROCESS:{self.process_id} Adaptive correction is not implemented yet."
            )

        pbar = tqdm(
            total=len(df),
            desc=f"Pkts2Sess (PID: {self.process_id})",
            unit="session",
            disable=not sys.stdout.isatty(),
        )
        total_rows = len(df)
        curr_row = 0
        found_packets = []
        for sess_idx, row in df.iterrows():
            curr_row += 1
            if sess_idx > self.max_sessions and self.max_sessions > 0:
                break
            pbar.update(1)
            # do everything in microseconds
            # else there will be precision issues!!
            start_dt = row[self.column_mapping.timestamp]
            start_ts = start_dt.timestamp() * 1e6
            end_ts = (
                start_ts + row[self.column_mapping.flow_duration] + self.correction_msec
            )
            # convert back to datetime
            end_dt = pd.to_datetime(end_ts, unit="us")
            # convert to seconds
            start_sec = start_dt.timestamp()
            end_sec = end_dt.timestamp()
            total_fwd_pkts = row[self.column_mapping.tot_fwd_pkts]
            total_bwd_pkts = row[self.column_mapping.tot_bwd_pkts]
            src_ip = row[self.column_mapping.src_ip]
            dst_ip = row[self.column_mapping.dst_ip]
            src_port = row[self.column_mapping.src_port]
            dst_port = row[self.column_mapping.dst_port]
            protocol = row[self.column_mapping.protocol]
            flow_label = row[self.column_mapping.label]

            labled_pkts = row[self.column_mapping.total_pkts]
            logger.info(
                f"PROCESS:{self.process_id} Processing session {curr_row}/{total_rows}: Flow ID {row[self.column_mapping.flow_id]} with {labled_pkts} labeled packets."
            )
            matched_pkts = []
            matched_pkt_idxs = []
            attempt = 1
            # try to reuse found_packets from previous session to avoid re-reading pcap
            while True:
                if attempt > 2 or len(matched_pkts) >= labled_pkts:
                    break
                if not found_packets or len(matched_pkts) < labled_pkts:
                    found_packets = packet_streamer.get_packets(
                        start_ts=start_sec,
                        end_ts=end_sec,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                    )

                attempt += 1
                first_pkt = None
                if found_packets:
                    for pkt_idx, pkt in enumerate(found_packets):
                        # break if we have enough packets
                        # bcz new pkts could be in different flow
                        if len(matched_pkts) >= labled_pkts:
                            break
                        if not (pkt.haslayer(IP) and pkt.haslayer(Ether)):
                            continue
                        ip_layer = pkt.getlayer(IP) or pkt.getlayer("IPv6")
                        if not ip_layer:
                            continue
                        if (ip_layer.src == src_ip and ip_layer.dst == dst_ip) or (
                            ip_layer.src == dst_ip and ip_layer.dst == src_ip
                        ):
                            is_pkt_matched = False
                            if pkt.haslayer(TCP):
                                if (
                                    pkt.getlayer(TCP).sport == src_port
                                    and pkt.getlayer(TCP).dport == dst_port
                                ) or (
                                    pkt.getlayer(TCP).sport == dst_port
                                    and pkt.getlayer(TCP).dport == src_port
                                ):
                                    is_pkt_matched = True
                            elif pkt.haslayer(UDP):
                                if (
                                    pkt.getlayer(UDP).sport == src_port
                                    and pkt.getlayer(UDP).dport == dst_port
                                ) or (
                                    pkt.getlayer(UDP).sport == dst_port
                                    and pkt.getlayer(UDP).dport == src_port
                                ):
                                    is_pkt_matched = True

                            if is_pkt_matched:
                                if self.anynomize:
                                    pkt = pkt.anonymize()
                                matched_pkts.append(pkt)
                                if not first_pkt:
                                    first_pkt = pkt
                                matched_pkt_idxs.append(pkt_idx)
                    pbar.set_postfix(
                        dict(
                            matched_pkts=len(matched_pkts),
                            total_pkts=labled_pkts,
                            flow_label=flow_label,
                        )
                    )
                num_forward_pkts = len(
                    [pkt for pkt in matched_pkts if pkt.src == first_pkt.src]
                )
                raw_bytes = [pkt.raw for pkt in matched_pkts]
                raw_lengths = [len(byt) for byt in raw_bytes]
                max_length = max(raw_lengths) if raw_lengths else 0
                min_length = min(raw_lengths) if raw_lengths else 0
                avg_length = sum(raw_lengths) / len(raw_lengths) if raw_lengths else 0
                num_backward_pkts = len(matched_pkts) - num_forward_pkts
                part = self.pcap_path.stem.split(".")[0]
                session_file_name = f"{flow_label}_{sess_idx}_{part}.pcap"
                labelled_session = {
                    "session_index": sess_idx,
                    "flow_id": row[self.column_mapping.flow_id],
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "start_time": start_dt,
                    "end_time": end_dt,
                    "start_timestamp": start_sec,
                    "end_timestamp": end_sec,
                    "total_matched_pkts": len(matched_pkts),
                    "total_labeled_pkts": labled_pkts,
                    "matched_forward_pkts": num_forward_pkts,
                    "matched_backward_pkts": num_backward_pkts,
                    "labled_forward_pkts": total_fwd_pkts,
                    "labled_backward_pkts": total_bwd_pkts,
                    "raw_bytes_max_length": max_length,
                    "raw_bytes_min_length": min_length,
                    "raw_bytes_avg_length": avg_length,
                    "session_file_name": session_file_name,
                    "flow_label": flow_label,
                    "input_file": file_path.name,
                }

                # NOTE: We save the session info to a CSV file after processing each session to ensure we have a record of all sessions,
                # even if the process is interrupted. This also allows us to track progress and debug any issues with specific sessions.
                # save session info to csv
                with open(self.label_file, "a") as f:
                    keys = labelled_session.keys()
                    if f.tell() == 0:
                        f.write(",".join(keys) + "\n")
                    # write session info
                    f.write(
                        ",".join([str(labelled_session[key]) for key in keys]) + "\n"
                    )
                if not matched_pkts:
                    continue
                if self.write_session_pcap:
                    # save session packets to a pcap file
                    session_pcap_path = output_path / "session_pcaps"
                    if not session_pcap_path.exists():
                        session_pcap_path.mkdir(parents=True, exist_ok=True)
                    session_pcap_path = session_pcap_path / session_file_name
                    wrpcap(str(session_pcap_path), matched_pkts)

                # remove matched packets from found_packets
                found_packets = [
                    pkt
                    for idx, pkt in enumerate(found_packets)
                    if idx not in matched_pkt_idxs
                ]

            labelled_sessions.append(
                Session(
                    index=sess_idx,
                    filename=session_file_name,
                    start_time=start_dt,
                    end_time=end_dt,
                    packets=matched_pkts,
                    interval=end_dt - start_dt,
                    raw_bytes=raw_bytes,
                    label=flow_label,
                )
            )

            if len(labelled_sessions) >= self.write_every:
                self.sessions_to_image(labelled_sessions)
                labelled_sessions = []
                # Force garbage collection after batch processing

                gc.collect()

            logger.info(
                f"PROCESS:{self.process_id} Processed session {curr_row}/{total_rows}: {session_file_name} with {len(matched_pkts)}/{labled_pkts} matched packets."
            )
            # Memory cleanup - Clear large variables after processing each session
            del matched_pkts, raw_bytes, raw_lengths
        pbar.close()
        return labelled_sessions

    def extract_session_features(self, session_bytes):
        """
        Extract grayscale array features from session packet bytes.

        Args:
            session_bytes (list): List of packet bytes for a session.
        Returns:
            np.ndarray: 2D grayscale array representing the session.
        """
        max_packets = len(session_bytes)
        bytes_per_packet = max([len(byt) for byt in session_bytes])
        # Initialize arrays
        grayscale_data = np.zeros((max_packets, bytes_per_packet), dtype=np.uint8)

        # Process up to max_packets
        processed_packets = 0
        for i, packet in enumerate(session_bytes):
            try:
                packet = packet
                raw_bytes = raw(packet)

                # Extract first bytes_per_packet bytes
                packet_data = raw_bytes[:bytes_per_packet]

                # Pad if necessary
                if len(packet_data) < bytes_per_packet:
                    packet_data += b"\x00" * (bytes_per_packet - len(packet_data))

                # Convert to numpy array
                packet_array = np.frombuffer(packet_data, dtype=np.uint8)

                # Store in both formats
                grayscale_data[processed_packets] = packet_array

                processed_packets += 1

                # Clean up temporary variables for large packets
                del packet_data, packet_array, raw_bytes

            except Exception as e:
                logger.error(
                    f"PROCESS:{self.process_id} Error processing packet {i}: {e} \n {traceback.format_exc()}"
                )
                continue

        return grayscale_data

    def normalized_features(self, packets: list["Packet"]):
        """
        Generate normalized byte frequency image for session payloads.

        Args:
            packets (list[Packet]): List of packets in the session.
        Returns:
            np.ndarray: 2D normalized byte frequency image.
        """
        num_pkts = len(packets)
        image = np.zeros((num_pkts, 256), dtype=np.float32)

        for i, pkt in enumerate(packets):
            # Extract payload bytes (handles different packet representations)
            if hasattr(pkt, "load"):
                raw_bytes = bytes(pkt.load) if pkt.load else b""
            elif isinstance(pkt, bytes):
                raw_bytes = pkt
            else:
                raw_bytes = b""

            if not raw_bytes:
                # Empty payload results in zero vector
                continue

            # Calculate byte frequency distribution
            byte_counts = np.zeros(256, dtype=np.float32)
            for byte_val in raw_bytes:
                byte_counts[byte_val] += 1

            # Packet-specific normalization (as per ByteStack-ID)
            max_freq = byte_counts.max()
            if max_freq > 0:
                byte_counts /= max_freq

            image[i, :] = byte_counts

            # Clean up temporary variables for memory management
            del byte_counts, raw_bytes

        image = (image * 255).astype(np.uint8)
        return image

    def extract_sessions(self):
        """
        Extract sessions from loaded packets and return session objects.
        """
        if not self.packet_buffer:
            logger.warning("No packets found in the PCAP file.")
            return
        logger.info(
            f"PROCESS:{self.process_id} Extracting sessions from {len(self.packet_buffer)} packets."
        )

        logger.info(
            f"PROCESS:{self.process_id} Processing interval: {self.interval} seconds"
        )
        self.sessions = self.packets_to_labelled_sessions(
            self.packet_buffer, df=self.label_df
        )

        return self.sessions

    def sessions_to_image(self, sessions: list["Session"]):
        """
        Convert session objects to grayscale images and save them.

        Args:
            sessions (list[Session]): List of session objects.
        """
        if not sessions:
            return
        # Use sequential processing for small batches
        for session in tqdm(
            sessions,
            desc=f"Session2Image (PID: {self.process_id})",
            unit="session",
            disable=not sys.stdout.isatty(),
        ):
            if not session.packets:
                continue
            img_name = session.filename.replace(".pcap", ".png")
            image_dir = self.out_dir / "session_images" / img_name
            if not image_dir.parent.exists():
                image_dir.parent.mkdir(parents=True)
            grayscale_array = self.extract_session_features(session.raw_bytes)
            if self.write_array:
                header_arrays = session.header_arrays
                layer_names = header_arrays.keys()
                for layer in layer_names:
                    if layer not in self.layer_names:
                        logger.info(
                            f"PROCESS:{self.process_id} Found new layer: {layer}. Total unique layers so far: {len(self.layer_names) + 1}"
                        )
                        self.layer_names.add(layer)
                # write header_arrays to npz array with keys
                npz_pth = str(image_dir).replace(".png", ".npz")
                header_arrays["layer_order"] = session.all_layer_names
                header_arrays["session_image"] = grayscale_array
                np.savez_compressed(npz_pth, **header_arrays)

                # remove layer_order
                del header_arrays["layer_order"]
                del header_arrays["session_image"]
            if self.write_image:
                # Extract features
                normalized_array = self.normalized_features(session.packets)
                cv2.imwrite(str(image_dir), grayscale_array)
                cv2.imwrite(
                    str(image_dir).replace(".png", "_normalized.png"), normalized_array
                )

                # write layer arrays as separate images
                for layer, array in header_arrays.items():
                    img_path = str(image_dir).replace(".png", f"_{layer}.png")
                    cv2.imwrite(img_path, array)

                # Clean up arrays after saving to free memory
                del grayscale_array, normalized_array

        logger.info(
            f"PROCESS:{self.process_id} Saved {len(sessions)} session images to {self.out_dir}"
        )

        # Force garbage collection after processing batch of sessions
        gc.collect()

    def run(self):
        """
        Run the feature extraction and session processing pipeline.
        """
        # Load packets from PCAP file
        if self.packet_streamer is None:
            self.load()
        else:
            logger.info(
                f"PROCESS:{self.process_id} Packets already loaded. Skipping load step."
            )
        if not self.packet_streamer:
            logger.error("No packets loaded. Exiting.")
            return
        logger.info(f"PROCESS:{self.process_id} Starting feature extraction...")
        self.sessions = self.packets_to_labelled_sessions(
            self.packet_streamer, self.label_df
        )
        logger.info(
            f"PROCESS:{self.process_id} Extracted {len(self.sessions)} sessions successfully."
        )
        # Save remaining session images
        self.sessions_to_image(self.sessions)
        logger.info(
            f"PROCESS:{self.process_id} Feature extraction completed successfully."
        )


def run_extractor(
    process_id: int,
    pcap_path: Path,
    label_df: pd.DataFrame,
    out_dir: Path,
    min_labeled_pkts: int = -1,
    max_labeled_pkts: int = -1,
    temp_dir: Path | None = None,
    use_apptainer: bool = True,
    container: str = "docker://cincan/tshark",
    use_tshark: bool = True,
    write_array: bool = False,
    write_image: bool = False,
    column_mapping: ColumnMapping = ColumnMapping(),
    write_every: int = 100,
):
    """
    Multiprocessing entry point for session feature extraction.

    Args:
        process_id (int): Process ID for multiprocessing.
        pcap_path (Path): Path to the PCAP file.
        label_df (pd.DataFrame): DataFrame with session/label information.
        out_dir (Path): Output directory for results.
        min_labeled_pkts (int): Minimum labeled packets per session.
        max_labeled_pkts (int): Maximum labeled packets per session.
        temp_dir (Path): Temporary directory.
        use_apptainer (bool): Use Apptainer for containerization.
        container (str): Container image.
        use_tshark (bool): Use Tshark for packet parsing.
        write_array (bool): Save session arrays.
        write_image (bool): Save session images.
        column_mapping (ColumnMapping): Column mapping for CSVs.
    """
    extractor = PCAPSessionFeatureExtractor(
        out_dir=out_dir,
        write_every=write_every,
        min_labeled_pkts=min_labeled_pkts,
        max_labeled_pkts=max_labeled_pkts,
        process_id=process_id,
        adaptive_correction_msec=False,
        temp_dir=temp_dir,
        use_apptainer=use_apptainer,
        container=container,
        use_tshark=use_tshark,
        write_array=write_array,
        write_image=write_image,
        column_mapping=column_mapping,
    )
    extractor.load(pcap_path=pcap_path, label_df=label_df)
    extractor.run()
    extractor.packet_streamer.cleanup()

    # write layer names to a text file
    layer_names_file = out_dir / f"layer_names_{process_id}.txt"
    with open(layer_names_file, "w") as f:
        for layer in extractor.layer_names:
            f.write(layer + "\n")
