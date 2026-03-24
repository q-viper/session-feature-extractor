#!/bin/bash -l
#
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=64
#SBATCH --time=24:00:00
#SBATCH --export=NONE
#SBATCH --output=rosids23_pcap_to_image.out

unset SLURM_EXPORT_ENV
module load python
# export proxy
export http_proxy=http://proxy:80
export https_proxy=http://proxy:80
# pip install -e .

# DNP3, IEC104, ROSIDS23 have different column names for timestamp, flow duration, total packets, etc.
# dataset_type = "ROSIDS" # for ROSIDS23 dataset

export DATA_DIR="$WORK/dataset/ROSIDS23"
export OUT_DIR="$WORK/dataset/rosids23_session_images_new"
# unzip all .zip files inside datadir to $TMPDIR
for file in $DATA_DIR/*.zip; do
    unzip -q "$file" -d "$TMPDIR"
done

# copy mapping.json to $TMPDIR
cp $DATA_DIR/mapping.json $TMPDIR

# move all unzipped pcap and csv files from sub folders in $TMPDIR to $TMPDIR
# and ignore error if no such files
mv $TMPDIR/**/*.pcap $TMPDIR 2>/dev/null
mv $TMPDIR/**/*.csv $TMPDIR 2>/dev/null

# now install apptainer
apptainer pull cincan_tshark.sif docker://cincan/tshark
# verify installation
apptainer exec --no-home --cleanenv cincan_tshark.sif tshark --version
apptainer exec --no-home --cleanenv cincan_tshark.sif editcap --version

# Increase file limits for Tshark
ulimit -n 65535

# Isolate Apptainer cache to RAM/Temp disk so 64 instances don't lock each other out
export APPTAINER_CACHEDIR=$TMPDIR/apptainer_cache
export APPTAINER_TMPDIR=$TMPDIR/apptainer_tmp
mkdir -p $APPTAINER_CACHEDIR $APPTAINER_TMPDIR

# set number of threads to requested cpus-per-task
export OMP_NUM_THREADS=$SLURM_CPUS_PER_TASK
# for Slurm version >22.05: cpus-per-task has to be set again for srun
export SRUN_CPUS_PER_TASK=$SLURM_CPUS_PER_TASK

# max_samples = 10 # for testing
# max_samples = -1 # for full dataset
export max_samples=-1

python3 $HOME/dip_sids/session-feature-extractor-main/examples/extraction.py \
    --data-dir "$TMPDIR" \
    --project-dir "$HOME/dip_sids" \
    --out-dir "$OUT_DIR" \
    --compress-to "$DATA_DIR/session_images.zip" \
    --temp-dir "$TMPDIR" \
    --num-processes $SLURM_CPUS_PER_TASK \
    --use-apptainer \
    --container "$HOME/dip_sids/cincan_tshark.sif" \
    --max-samples $max_samples \
    --write-array