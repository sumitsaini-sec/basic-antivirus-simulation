import os
import hashlib
import shutil
from datetime import datetime

# Project folders and files
SCAN_FOLDER = "test_files"
QUARANTINE_FOLDER = "quarantine"
SIGNATURE_FILE = "malware_signatures.txt"
REPORT_FILE = "scan_report.txt"


def calculate_sha256(file_path):
    """Returns the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()

    try:
        with open(file_path, "rb") as file:
            while True:
                data = file.read(4096)

                if not data:
                    break

                sha256_hash.update(data)

        return sha256_hash.hexdigest()

    except Exception as error:
        print(f"[ERROR] Could not scan {file_path}: {error}")
        return None


def load_signatures():
    """Loads malware hashes from malware_signatures.txt."""
    signatures = {}

    try:
        with open(SIGNATURE_FILE, "r") as file:
            for line in file:
                line = line.strip()

                if "|" in line:
                    file_hash, malware_name = line.split("|", 1)
                    signatures[file_hash] = malware_name

    except FileNotFoundError:
        print("[ERROR] Signature database not found.")

    return signatures


def get_safe_quarantine_path(file_name):
    """Prevents overwriting if a file with the same name already exists."""
    destination = os.path.join(QUARANTINE_FOLDER, file_name)

    if not os.path.exists(destination):
        return destination

    name, extension = os.path.splitext(file_name)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    return os.path.join(
        QUARANTINE_FOLDER,
        f"{name}_{timestamp}{extension}"
    )


def scan_files():
    """Scans files, checks their hashes, and quarantines detected files."""
    print("=" * 55)
    print("        BASIC ANTIVIRUS SIMULATION")
    print("=" * 55)

    os.makedirs(QUARANTINE_FOLDER, exist_ok=True)

    signatures = load_signatures()

    if not signatures:
        print("[WARNING] No malware signatures loaded.")
        return

    print(f"[INFO] Loaded {len(signatures)} malware signature(s).")
    print(f"[INFO] Scanning folder: {SCAN_FOLDER}\n")

    total_files = 0
    clean_files = 0
    detected_files = 0
    report_lines = []

    report_lines.append("BASIC ANTIVIRUS SIMULATION - SCAN REPORT")
    report_lines.append(f"Scan Date & Time: {datetime.now()}")
    report_lines.append("-" * 60)

    for root, folders, files in os.walk(SCAN_FOLDER):
        for file_name in files:
            total_files += 1

            file_path = os.path.join(root, file_name)
            file_hash = calculate_sha256(file_path)

            if file_hash is None:
                report_lines.append(f"ERROR | {file_name} | Could not scan file")
                continue

            print(f"[SCAN] Checking: {file_name}")

            if file_hash in signatures:
                malware_name = signatures[file_hash]
                quarantine_path = get_safe_quarantine_path(file_name)

                shutil.move(file_path, quarantine_path)

                detected_files += 1

                print(f"[ALERT] Malicious file detected: {file_name}")
                print(f"[ACTION] Moved to quarantine: {quarantine_path}\n")

                report_lines.append(
                    f"DETECTED | {file_name} | {malware_name} | SHA-256: {file_hash}"
                )

            else:
                clean_files += 1

                print(f"[CLEAN] No known signature found.\n")

                report_lines.append(
                    f"CLEAN | {file_name} | SHA-256: {file_hash}"
                )

    report_lines.append("-" * 60)
    report_lines.append(f"Total files scanned: {total_files}")
    report_lines.append(f"Clean files: {clean_files}")
    report_lines.append(f"Malicious files detected: {detected_files}")

    with open(REPORT_FILE, "w") as report:
        report.write("\n".join(report_lines))

    print("=" * 55)
    print("SCAN COMPLETED")
    print(f"Total files scanned: {total_files}")
    print(f"Clean files: {clean_files}")
    print(f"Malicious files detected: {detected_files}")
    print(f"Report saved as: {REPORT_FILE}")
    print("=" * 55)


scan_files()