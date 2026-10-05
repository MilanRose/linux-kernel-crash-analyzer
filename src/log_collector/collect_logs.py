from datetime import datetime
from pathlib import Path
import subprocess


# Project root directory
PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Folder where raw logs will be stored
RAW_DIR = PROJECT_ROOT / "data" / "raw"


def collect_kernel_logs():
    """Collect kernel logs using dmesg."""
    
    result = subprocess.run(
        ["dmesg"],
        capture_output=True,
        text=True,
        check=True
    )

    return result.stdout


def save_log(log_data):
    """Save collected logs with a timestamped filename."""

    RAW_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    file_path = RAW_DIR / f"kernel_log_{timestamp}.log"

    file_path.write_text(log_data, encoding="utf-8")

    return file_path


if __name__ == "__main__":

    print("Collecting Linux kernel logs...")

    logs = collect_kernel_logs()

    file_path = save_log(logs)

    print(f"Kernel log saved to: {file_path}")