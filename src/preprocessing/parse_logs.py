import re
import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
RAW_DIR = PROJECT_ROOT / "data" / "raw"
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"


def extract_error_type(log):
    """
    Identify the type of kernel error from a log.
    """

    patterns = {
        "NULL_POINTER_DEREFERENCE": r"NULL pointer dereference",
        "PAGE_FAULT": r"page fault",
        "KERNEL_PANIC": r"Kernel panic",
        "OOPS": r"\bOops\b",
        "GENERAL_PROTECTION_FAULT": r"general protection fault",
        "OUT_OF_MEMORY": r"Out of memory|oom-killer",
        "BUG": r"\bBUG:",
    }

    for error_type, pattern in patterns.items():
        if re.search(pattern, log, re.IGNORECASE):
            return error_type

    return "UNKNOWN"


def extract_function(log):
    """
    Extract the function mentioned after RIP.
    """

    match = re.search(r"RIP:.*?:(\w+)\+", log)

    if match:
        return match.group(1)

    return "UNKNOWN"


def extract_module(log):
    """
    Extract the module from 'Modules linked in'.
    """

    match = re.search(r"Modules linked in:\s*(.*)", log)

    if match:
        modules = match.group(1).strip()
        return modules.split()[0] if modules else "UNKNOWN"

    return "UNKNOWN"


def extract_process(log):
    """
    Extract process name from Comm field.
    """

    match = re.search(r"Comm:\s*([^\s]+)", log)

    if match:
        return match.group(1)

    return "UNKNOWN"


def extract_pid(log):
    """
    Extract process ID.
    """

    match = re.search(r"PID:\s*(\d+)", log)

    if match:
        return int(match.group(1))

    return None

def extract_cpu(log):
    """
    Extract CPU number from the crash log.
    """

    match = re.search(r"CPU:\s*(\d+)", log)

    if match:
        return int(match.group(1))

    return None

def extract_address(log):
    """
    Extract the memory address involved in the crash.
    """

    match = re.search(r"address:\s*([0-9a-fA-Fx]+)", log)

    if match:
        return match.group(1)

    return "UNKNOWN"

def extract_call_trace(log):
    """
    Extract the function call trace from the crash log.
    """

    match = re.search(
        r"Call Trace:\s*(.*?)(?:\nModules linked in:|\Z)",
        log,
        re.DOTALL
    )

    if not match:
        return []

    lines = match.group(1).splitlines()

    call_trace = []

    for line in lines:
        line = line.strip()

        if line:
            call_trace.append(line)

    return call_trace

def determine_severity(error_type):
    """
    Assign severity based on the detected error type.
    """

    if error_type == "KERNEL_PANIC":
        return "CRITICAL"

    if error_type in {
        "NULL_POINTER_DEREFERENCE",
        "PAGE_FAULT",
        "GENERAL_PROTECTION_FAULT",
        "OOPS",
        "BUG",
        "OUT_OF_MEMORY"
    }:
        return "HIGH"

    return "UNKNOWN"


def parse_log(log_path):
    """
    Parse a raw kernel log into structured information.
    """

    log = log_path.read_text(encoding="utf-8", errors="ignore")

    error_type = extract_error_type(log)

    record = {
        "Crash_ID": log_path.stem,
        "Error_Type": error_type,
        "Module": extract_module(log),
        "Function": extract_function(log),
        "Process": extract_process(log),
        "PID": extract_pid(log),
        "CPU": extract_cpu(log),
        "Call_Trace": extract_call_trace(log),
        "Address": extract_address(log),
        "Severity": determine_severity(error_type),
        "Raw_Log": log
    }

    return record


def main():

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    log_files = list(RAW_DIR.glob("*.log"))

    if not log_files:
        print("No kernel log files found.")
        return

    for log_file in log_files:

        record = parse_log(log_file)

        output_file = PROCESSED_DIR / f"{log_file.stem}.json"

        output_file.write_text(
            json.dumps(record, indent=4),
            encoding="utf-8"
        )

        print(f"Parsed: {log_file.name}")
        print(f"Error Type: {record['Error_Type']}")
        print(f"Severity: {record['Severity']}")
        print(f"Saved to: {output_file}")


if __name__ == "__main__":
    main()
