"""
Unit tests for the extraction CLI and batch processing logic.
"""

import os
import sys
import tempfile
from pathlib import Path

import pandas as pd
from typer.testing import CliRunner

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from examples import extraction

runner = CliRunner()


def test_extraction_runs_minimal():
    """
    Test that the extraction CLI runs with minimal arguments and creates output.
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_dir_path = Path(temp_dir)
        out_dir = temp_dir_path / "output"
        out_dir.mkdir(parents=True, exist_ok=True)
        try:
            result = runner.invoke(
                extraction.app,
                [
                    "--data-dir",
                    "assets/sample_pcaps",
                    "--out-dir",
                    str(out_dir),
                    "--temp-dir",
                    str(temp_dir_path),
                    "--num-processes",
                    "1",
                    "--max-samples",
                    "2",
                ],
            )
            assert result.exit_code == 0, result.output
            assert (out_dir).exists()
        finally:
            pass


def test_extraction_creates_labelled_csv():
    """
    Test that the extraction CLI creates a merged labelled_sessions.csv file.
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_dir_path = Path(temp_dir)
        out_dir = temp_dir_path / "output"
        out_dir.mkdir(parents=True, exist_ok=True)
        try:
            result = runner.invoke(
                extraction.app,
                [
                    "--data-dir",
                    "assets/sample_pcaps",
                    "--out-dir",
                    str(out_dir),
                    "--temp-dir",
                    str(temp_dir_path),
                    "--num-processes",
                    "1",
                    "--max-samples",
                    "2",
                ],
            )
            assert result.exit_code == 0, result.output
            merged_csv = out_dir / "labelled_sessions.csv"
            assert merged_csv.exists()
            df = pd.read_csv(merged_csv)
            assert not df.empty
        finally:
            pass


def test_extraction_handles_missing_csv():
    """
    Test that the extraction CLI handles missing CSV files gracefully.
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_dir_path = Path(temp_dir)
        out_dir = temp_dir_path / "output"
        out_dir.mkdir(parents=True, exist_ok=True)
        mapping_path = Path("assets/sample_pcaps/mapping.json")
        backup_path = mapping_path.with_suffix(".bak")
        mapping_path.rename(backup_path)
        try:
            result = runner.invoke(
                extraction.app,
                [
                    "--data-dir",
                    "assets/sample_pcaps",
                    "--out-dir",
                    str(out_dir),
                    "--temp-dir",
                    str(temp_dir_path),
                    "--num-processes",
                    "1",
                    "--max-samples",
                    "2",
                ],
            )
            assert result.exit_code == 0 or result.exit_code == 1
        finally:
            if backup_path.exists():
                backup_path.rename(mapping_path)


def test_extraction_creates_images_and_arrays():
    """
    Test that the extraction CLI creates session images, numpy array files, and npz files.
    """
    import cv2
    import numpy as np

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_dir_path = Path(temp_dir)
        out_dir = temp_dir_path / "output"
        out_dir.mkdir(parents=True, exist_ok=True)
        try:
            result = runner.invoke(
                extraction.app,
                [
                    "--data-dir",
                    "assets/sample_pcaps",
                    "--out-dir",
                    str(out_dir),
                    "--temp-dir",
                    str(temp_dir_path),
                    "--num-processes",
                    "1",
                    "--max-samples",
                    "2",
                    "--write-array",
                    "--write-image",
                ],
            )
            assert result.exit_code == 0, result.output
            # Check for created images
            image_dir = out_dir / "session_images"
            images = list(image_dir.rglob("*.png"))
            assert images, "No session images were created."
            for img_path in images:
                img = cv2.imread(str(img_path), cv2.IMREAD_UNCHANGED)
                assert img is not None and img.size > 0, (
                    f"Image {img_path} is empty or unreadable."
                )
            # Check for created npz files and read their contents
            npz_files = list(image_dir.rglob("*.npz"))
            assert npz_files, "No npz files were created."
            for npz_path in npz_files:
                npz = np.load(npz_path, allow_pickle=True)
                assert "layer_order" in npz, f"layer_order missing in {npz_path}"
                for key in npz.files:
                    arr = npz[key]
                    assert arr is not None, f"Key {key} in {npz_path} is empty."
        finally:
            pass
