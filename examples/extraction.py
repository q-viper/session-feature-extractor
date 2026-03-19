"""
examples.extraction
-------------------

CLI batch extraction script for session-based feature extraction from PCAP files using Typer.
"""

import gc
import json
import multiprocessing
from pathlib import Path

import pandas as pd
import typer
from loguru import logger

from sfe.data.extractor import run_extractor
from sfe.defs import ColumnMapping

app = typer.Typer(help="PCAP to Session Image Converter")


@app.command()
def main(
    project_dir: str = typer.Option(".", help="Working directory for logs and outputs"),
    data_dir: str = typer.Option(
        "../assets/sample_pcaps",
        help="Root directory containing PCAP files and CSV labels",
    ),
    out_dir: str = typer.Option(
        "../temp/my_output", help="Root directory for output images and sessions"
    ),
    temp_dir: str = typer.Option(
        "../temp/my_temp", help="Temporary directory for intermediate files"
    ),
    num_processes: int = typer.Option(
        1, help="Number of processes to use for processing"
    ),
    compress_to: str = typer.Option(
        "../temp/processed_sessions.zip",
        help="Directory to zip and move processed files to",
    ),
    use_apptainer: bool = typer.Option(
        False, help="Use Apptainer for containerized processing"
    ),
    use_tshark: bool = typer.Option(True, help="Use Tshark for packet processing"),
    container: str = typer.Option(
        "docker://cincan/tshark", help="Container image to use with Apptainer"
    ),
    write_array: bool = typer.Option(
        True,
        help="Save each layer as separate array in the npy file. If false, only the full packet bytes will be saved.",
    ),
    write_image: bool = typer.Option(True, help="Save the session as an image."),
    hours_to_subtract: int = typer.Option(
        3, help="Number of hours to subtract from CSV timestamps to match PCAP timing"
    ),
    min_labeled_pkts: int = typer.Option(
        -1, help="Minimum number of labeled packets to include a session"
    ),
    max_labeled_pkts: int = typer.Option(
        -1, help="Maximum number of labeled packets to include a session"
    ),
    max_samples: int = typer.Option(
        -1,
        help="Maximum number of sessions to process from first row (after filtering)",
    ),
):
    """
    Main entry point for batch session extraction from PCAP files using Typer CLI.

    Args:
        project_dir (str): Working directory for logs and outputs.
        data_dir (str): Directory containing PCAP files and CSV labels.
        out_dir (str): Directory for output images and sessions.
        temp_dir (str): Temporary directory for intermediate files.
        num_processes (int): Number of processes to use for multiprocessing.
        compress_to (str): Path to zip and move processed files to.
        use_apptainer (bool): Use Apptainer for containerized processing.
        use_tshark (bool): Use Tshark for packet processing.
        container (str): Container image to use with Apptainer.
        write_array (bool): Save each layer as separate array in the npy file.
        write_image (bool): Save the session as an image.
        hours_to_subtract (int): Hours to subtract from CSV timestamps to match PCAP timing.
        min_labeled_pkts (int): Minimum number of labeled packets to include a session.
        max_labeled_pkts (int): Maximum number of labeled packets to include a session.
        max_samples (int): Maximum number of sessions to process after filtering.
    """
    log_path = Path(project_dir) / "logs" / "pcap_to_img_mp.log"
    logger.add(log_path)

    column_mapping = ColumnMapping(
        timestamp="date",
        flow_duration="duration",
        tot_fwd_pkts="TotalFwdPkts",
        tot_bwd_pkts="TotalBwdPkts",
        src_ip="source IP",
        dst_ip="destination IP",
        src_port="source port",
        dst_port="destination port",
        protocol="protocol",
        label="Label",
        flow_id="flow ID",
        flow_label="Label",
        total_pkts="total_pkts",
    )

    pcap_root = Path(data_dir)
    if out_dir:
        out_dir = Path(out_dir)
        if not out_dir.exists():
            out_dir.mkdir(parents=True, exist_ok=True)
    else:
        out_dir = pcap_root.parent / f"{pcap_root.name}_sessions"
    project_dir = Path(project_dir)
    if temp_dir:
        temp_dir = Path(temp_dir)
        if not temp_dir.exists():
            temp_dir.mkdir(parents=True, exist_ok=True)
    else:
        temp_dir = project_dir / "temp"
        if not temp_dir.exists():
            temp_dir.mkdir(parents=True, exist_ok=True)
    completed_attacks = []

    pcap_files = list(pcap_root.glob("*.pcap"))
    mapping_path = pcap_root / "mapping.json"

    cpu_cores = max(multiprocessing.cpu_count() - 1, 1)
    if num_processes > 0:
        cpu_cores = min(cpu_cores, num_processes)
    logger.info(f"Using {cpu_cores} CPU cores.")

    with open(mapping_path, "r") as f:
        mapping = json.load(f)
    pcap_files.sort(key=lambda x: x.stat().st_size, reverse=True)
    for idx, pcap_file in enumerate(pcap_files):
        logger.info(f"Processing {pcap_file.name}...")

        atk_name = pcap_file.stem.split("-")[-1]

        if atk_name in completed_attacks:
            logger.info(
                f"Skipping {pcap_file.name} as attack {atk_name} in completed attacks"
            )
            continue
        if pcap_file.stem not in mapping:
            logger.warning(
                f"PCAP file {pcap_file.name} not found in mapping. Skipping."
            )
            continue
        csv_name = mapping[pcap_file.stem] + ".csv"
        csv_file = pcap_file.parent / csv_name

        completed_csv_files = list(out_dir.rglob(f"*{atk_name}*csv"))
        completed_df = pd.DataFrame()
        for completed_csv in completed_csv_files:
            try:
                temp_df = pd.read_csv(completed_csv)
                completed_df = pd.concat([completed_df, temp_df], ignore_index=True)
            except Exception as e:
                logger.error(f"Error reading completed CSV file ({completed_csv}): {e}")
                completed_csv.unlink()
        logger.info(
            f"Found {len(completed_df)} completed sessions for attack {atk_name} from {len(completed_csv_files)} files."
        )

        if not csv_file.exists():
            logger.warning(f"CSV file not found for {pcap_file.name}")
            continue
        df = pd.read_csv(csv_file)
        df.columns = [c.strip() for c in df.columns]

        df[column_mapping.timestamp] = pd.to_datetime(df[column_mapping.timestamp])
        df[column_mapping.timestamp] = df[column_mapping.timestamp] - pd.Timedelta(
            hours=hours_to_subtract
        )
        df = df.sort_values(by=column_mapping.timestamp, ascending=True)

        logger.info(
            f"{csv_file} Labels: {df[column_mapping.flow_label].value_counts()}"
        )

        def map_label(x):
            return x

        df.Label = df.Label.apply(map_label)
        df[column_mapping.total_pkts] = (
            df[column_mapping.tot_fwd_pkts] + df[column_mapping.tot_bwd_pkts]
        )

        _min_labeled_pkts = min_labeled_pkts
        _max_labeled_pkts = max_labeled_pkts
        if _max_labeled_pkts <= 0:
            _max_labeled_pkts = df[column_mapping.total_pkts].quantile(0.80)

        logger.info(f"Total sessions in CSV before filtering: {len(df)}")
        if _min_labeled_pkts > 0:
            df = df[df[column_mapping.total_pkts] >= _min_labeled_pkts]
        if _max_labeled_pkts > 0:
            df = df[df[column_mapping.total_pkts] <= _max_labeled_pkts]
        logger.info(f"Total sessions in CSV after filtering: {len(df)}")

        if not completed_df.empty:
            initial_len = len(df)
            completed_df["session_index"] = completed_df["session_index"]
            completed_indices = set(completed_df["session_index"].unique())
            ndf = df[~df.index.isin(completed_indices)]
            logger.info(
                f"Removed {initial_len - len(ndf)} completed sessions from processing."
            )
            df = ndf

        del completed_df

        num_rows = len(df)
        if num_rows == 0:
            logger.info(f"No sessions to process for {pcap_file.name}. Skipping.")
            continue
        if max_samples > 0 and num_rows > max_samples:
            df = df.head(max_samples)
            num_rows = len(df)
            logger.info(f"Sampled down to {num_rows} sessions for processing.")
        num_rows_per_core = num_rows // cpu_cores
        if num_rows_per_core < 1:
            raise ValueError(
                f"Not enough rows ({num_rows}) for the number of CPU cores ({cpu_cores})"
            )
        if num_rows % cpu_cores > 0:
            num_rows_per_core += 1
        logger.info(
            f"Splitting {num_rows} rows into chunks of {num_rows_per_core} for {cpu_cores} cores"
        )

        df_chunks = [
            df.iloc[i : i + num_rows_per_core]
            for i in range(0, num_rows, num_rows_per_core)
        ]
        logger.info(f"Created {len(df_chunks)} chunks for processing.")
        with multiprocessing.Pool(processes=cpu_cores) as pool:
            pool.starmap(
                run_extractor,
                [
                    (
                        process_id + 1,
                        pcap_file,
                        df_chunk,
                        out_dir,
                        _min_labeled_pkts,
                        _max_labeled_pkts,
                        temp_dir,
                        use_apptainer,
                        container,
                        use_tshark,
                        write_array,
                        write_image,
                        column_mapping,
                    )
                    for process_id, df_chunk in enumerate(df_chunks)
                ],
            )
            pool.close()
            pool.join()

        del df, df_chunks
        gc.collect()
        logger.info(f"Completed {idx}/{len(pcap_files)}")
    all_label_files = list(out_dir.glob("labelled_sessions_*.csv"))
    if all_label_files:
        merged_df = pd.concat(
            [pd.read_csv(f) for f in all_label_files], ignore_index=True
        )
        merged_df.to_csv(out_dir / "labelled_sessions.csv", index=False)
        logger.info(f"Merged {len(all_label_files)} labelled session files into one.")

    if compress_to:
        import shutil

        zip_path = Path(compress_to)
        shutil.make_archive(
            base_name=str(zip_path).replace(".zip", ""),
            format="zip",
            root_dir=out_dir,
        )
        logger.info(f"Zipped processed sessions to {zip_path}")


if __name__ == "__main__":
    app()
