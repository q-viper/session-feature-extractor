import argparse
import gc
import json
import multiprocessing
from pathlib import Path

import pandas as pd
from loguru import logger

from sfe.data.extractor import run_extractor
from sfe.defs import ColumnMapping

# root dir
parser = argparse.ArgumentParser(description="PCAP to Session Image Converter")
parser.add_argument(
    "--project_dir",
    type=str,
    default=".",
    help="Working directory for logs and outputs",
)

parser.add_argument(
    "--data_dir",
    type=str,
    default="../assets/sample_pcaps",
    help="Root directory containing PCAP files and CSV labels",
)
parser.add_argument(
    "--out_dir",
    type=str,
    default="../temp/my_output",
    help="Root directory for output images and sessions",
)
parser.add_argument(
    "--temp_dir",
    type=str,
    default="../temp/my_temp",
    help="Temporary directory for intermediate files",
)
parser.add_argument(
    "--num_processes",
    type=int,
    default=1,
    help="Number of processes to use for processing",
)
parser.add_argument(
    "--compress_to",
    type=str,
    default="../temp/processed_sessions.zip",
    help="Directory to zip and move processed files to",
)
parser.add_argument(
    "--use_apptainer",
    action="store_true",
    default=False,
    help="Use Apptainer for containerized processing",
)
parser.add_argument(
    "--use_tshark",
    action="store_true",
    default=True,
    help="Use Tshark for packet processing",
)
parser.add_argument(
    "--container",
    type=str,
    default="docker://cincan/tshark",
    help="Container image to use with Apptainer",
)
parser.add_argument(
    "--write_array",
    action="store_true",
    default=True,
    help="A boolean to whether to save each layer as separate array in the npy file. If false, only the full packet bytes will be saved. Default is True.",
)
parser.add_argument(
    "--write_image",
    action="store_true",
    default=True,
    help="A boolean to whether to save the session as an image. Default is True.",
)
parser.add_argument(
    "--hours_to_subtract",
    type=int,
    default=3,
    help="Number of hours to subtract from CSV timestamps to match PCAP timing",
)
parser.add_argument(
    "--min_labeled_pkts",
    type=int,
    default=-1,
    help="Minimum number of labeled packets to include a session",
)
parser.add_argument(
    "--max_labeled_pkts",
    type=int,
    default=-1,
    help="Maximum number of labeled packets to include a session",
)
args = parser.parse_args()

log_path = Path(args.project_dir) / "logs" / "pcap_to_img_mp.log"

# log file in writing mode
logger.add(
    log_path,
)

column_mapping = ColumnMapping(
    timestamp="date",
    flow_duration="duration",
    total_pkts="TotPktsInFlow",  # or use a computed column if not present
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
)


if __name__ == "__main__":
    pcap_root = Path(args.data_dir)
    if args.out_dir:
        out_dir = Path(args.out_dir)
        if not out_dir.exists():
            out_dir.mkdir(parents=True, exist_ok=True)
    else:
        out_dir = pcap_root.parent / f"{pcap_root.name}_sessions"
    project_dir = Path(args.project_dir)
    if args.temp_dir:
        temp_dir = Path(args.temp_dir)
        if not temp_dir.exists():
            temp_dir.mkdir(parents=True, exist_ok=True)
    else:
        temp_dir = project_dir / "temp"
        if not temp_dir.exists():
            temp_dir.mkdir(parents=True, exist_ok=True)
    completed_attacks = []

    pcap_files = list(pcap_root.glob("*.pcap"))
    mapping_path = pcap_root / "mapping.json"

    # true cpu cores but not logical cores
    cpu_cores = max(multiprocessing.cpu_count() - 1, 1)
    if args.num_processes > 0:
        cpu_cores = min(cpu_cores, args.num_processes)
    logger.info(f"Using {cpu_cores} CPU cores.")

    # read mapping
    with open(mapping_path, "r") as f:
        mapping = json.load(f)
    # sort by size
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

        # read completed csv
        completed_csv_files = list(out_dir.rglob(f"*{atk_name}*csv"))
        completed_df = pd.DataFrame()
        for completed_csv in completed_csv_files:
            try:
                temp_df = pd.read_csv(completed_csv)
                completed_df = pd.concat([completed_df, temp_df], ignore_index=True)
            except Exception as e:
                logger.error(f"Error reading completed CSV file ({completed_csv}): {e}")
                # remove corrupted file
                completed_csv.unlink()
        logger.info(
            f"Found {len(completed_df)} completed sessions for attack {atk_name} from {len(completed_csv_files)} files."
        )

        if not csv_file.exists():
            logger.warning(f"CSV file not found for {pcap_file.name}")
            continue
        df = pd.read_csv(csv_file)
        df.columns = [
            c.strip() for c in df.columns
        ]  # strip whitespace from column names

        df[column_mapping.timestamp] = pd.to_datetime(df[column_mapping.timestamp])
        # subtract hours to match pcap timing
        df[column_mapping.timestamp] = df[column_mapping.timestamp] - pd.Timedelta(
            hours=args.hours_to_subtract
        )
        df = df.sort_values(by=column_mapping.timestamp, ascending=True)
        # df = df.sort_values(by="Flow Duration", ascending=True)

        logger.info(
            f"{csv_file} Labels: {df[column_mapping.flow_label].value_counts()}"
        )

        def map_label(x):
            return x

        df.Label = df.Label.apply(map_label)
        df["total_pkts"] = (
            df[column_mapping.tot_fwd_pkts] + df[column_mapping.tot_bwd_pkts]
        )

        min_labeled_pkts = args.min_labeled_pkts
        max_labeled_pkts = args.max_labeled_pkts
        # find max_labeled_pkts as 80 percentile if not set
        if max_labeled_pkts <= 0:
            max_labeled_pkts = df[column_mapping.total_pkts].quantile(0.80)

        logger.info(f"Total sessions in CSV before filtering: {len(df)}")
        # filter based on min and max labeled pkts
        if min_labeled_pkts > 0:
            df = df.query("total_pkts >= @min_labeled_pkts")
        if max_labeled_pkts > 0:
            df = df.query("total_pkts <= @max_labeled_pkts")
        logger.info(f"Total sessions in CSV after filtering: {len(df)}")

        if not completed_df.empty:
            initial_len = len(df)
            completed_df["session_index"] = completed_df["session_index"]
            # make it index
            completed_indices = set(completed_df["session_index"].unique())
            ndf = df[~df.index.isin(completed_indices)]
            logger.info(
                f"Removed {initial_len - len(ndf)} completed sessions from processing."
            )
            df = ndf

        del completed_df

        # get num rows
        num_rows = len(df)
        if num_rows == 0:
            logger.info(f"No sessions to process for {pcap_file.name}. Skipping.")
            continue
        num_rows_per_core = num_rows // cpu_cores
        if num_rows_per_core < 1:
            raise ValueError(
                f"Not enough rows ({num_rows}) for the number of CPU cores ({cpu_cores})"
            )

        # last core also takes the remainder
        if num_rows % cpu_cores > 0:
            num_rows_per_core += 1
        logger.info(
            f"Splitting {num_rows} rows into chunks of {num_rows_per_core} for {cpu_cores} cores"
        )

        # split df into chunks
        df_chunks = [
            df.iloc[i : i + num_rows_per_core]
            for i in range(0, num_rows, num_rows_per_core)
        ]
        logger.info(f"Created {len(df_chunks)} chunks for processing.")
        # now process then multiprocessing
        with multiprocessing.Pool(processes=cpu_cores) as pool:
            pool.starmap(
                run_extractor,
                [
                    (
                        process_id + 1,
                        pcap_file,
                        df_chunk,
                        out_dir,
                        min_labeled_pkts,
                        max_labeled_pkts,
                        temp_dir,
                        args.use_apptainer,
                        args.container,
                        args.use_tshark,
                        args.write_array,
                        args.write_image,
                        column_mapping,
                    )
                    for process_id, df_chunk in enumerate(df_chunks)
                ],
            )
            pool.close()
            pool.join()

        # Clean up memory after processing each file
        del df, df_chunks

        gc.collect()

        logger.info(f"Completed {idx}/{len(pcap_files)}")
    # at the end read all the labelled_sessions_*.csv and merge into one
    all_label_files = list(out_dir.glob("labelled_sessions_*.csv"))
    if all_label_files:
        merged_df = pd.concat(
            [pd.read_csv(f) for f in all_label_files], ignore_index=True
        )
        merged_df.to_csv(out_dir / "labelled_sessions.csv", index=False)
        logger.info(f"Merged {len(all_label_files)} labelled session files into one.")

    # Optionally zip and move processed files
    if args.compress_to:
        import shutil

        zip_path = Path(args.compress_to)
        shutil.make_archive(
            base_name=str(zip_path).replace(".zip", ""),
            format="zip",
            root_dir=out_dir,
        )
        logger.info(f"Zipped processed sessions to {zip_path}")
