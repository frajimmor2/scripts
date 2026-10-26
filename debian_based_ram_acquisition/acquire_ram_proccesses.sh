
#!/usr/bin/env bash

# Process memory acquisition using gcore.
# Usage: sudo ./memory_acquisition.sh /path/to/external/drive_or_dir

set -u
umask 333

# Check root privileges
if [[ "$(id -u)" -ne 0 ]]; then
    echo "[ERROR] This script must be executed with sudo."
    exit 1
fi

# Validate arguments
if [[ "$#" -ne 1 ]]; then
    echo "Usage: sudo $0 /path/to/mountpoint"
    exit 1
fi

MOUNT_POINT="$1"

# Check whether gcore is installed
if ! command -v gcore >/dev/null 2>&1; then
    echo "[ERROR] gcore is not installed or is not in PATH."
    echo "Install it using the appropriate package for your system."
    exit 1
fi

# Validate the external drive mount point
if [[ ! -d "$MOUNT_POINT" ]]; then
    echo "[ERROR] The specified directory does not exist: $MOUNT_POINT"
    exit 1
fi
:'
Uncomment if you also want to check if the path is a mount point
if ! mountpoint -q -- "$MOUNT_POINT"; then
    echo "[ERROR] The specified path is not a mount point."
    echo "Please provide the actual mounted external drive path."
    exit 1
fi
'
if [[ ! -w "$MOUNT_POINT" ]]; then
    echo "[ERROR] The mount point is not writable."
    exit 1
fi

# Create a unique acquisition directory
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
OUTPUT_DIR="${MOUNT_POINT}/memory_acquisition_${TIMESTAMP}"

if ! mkdir -p -- "$OUTPUT_DIR"; then
    echo "[ERROR] Could not create the output directory."
    exit 1
fi

LOG_FILE="${OUTPUT_DIR}/acquisition.log"
MANIFEST_FILE="${OUTPUT_DIR}/sha256_manifest.txt"

# Redirect output to both the terminal and the log file
exec > >(tee -a "$LOG_FILE") 2>&1

echo "=========================================="
echo " Process Memory Acquisition"
echo "=========================================="
echo "Start time: $(date --iso-8601=seconds)"
echo "Hostname: $(hostname)"
echo "Output directory: $OUTPUT_DIR"
echo "gcore path: $(command -v gcore)"
echo

# Record basic system information
{
    echo "Hostname: $(hostname)"
    echo "Kernel: $(uname -a)"
    echo "gcore version:"
    gcore --version 2>&1 || true
    echo "Mount information:"
    findmnt --target "$MOUNT_POINT" || true
    echo
} >> "${OUTPUT_DIR}/system_information.txt"

# Collect a snapshot of numeric process IDs
PIDS=()

for PROC_DIR in /proc/[0-9]*; do
    [[ -d "$PROC_DIR" ]] || continue

    PID="${PROC_DIR##*/}"

    if [[ "$PID" =~ ^[0-9]+$ ]]; then
        PIDS+=("$PID")
    fi
done

TOTAL=${#PIDS[@]}
SUCCESS=0
FAILED=0
SKIPPED=0

echo "[INFO] Processes identified: $TOTAL"
echo "[INFO] Starting acquisition..."
echo

# Acquire each process memory separately
for PID in "${PIDS[@]}"; do
    # Skip processes that have already terminated
    if [[ ! -d "/proc/$PID" ]]; then
        echo "[SKIPPED] PID $PID no longer exists."
        ((SKIPPED+=1))
        continue
    fi

    PROCESS_NAME=$(cat "/proc/$PID/comm" 2>/dev/null || echo "unknown")
    SAFE_NAME=$(printf '%s' "$PROCESS_NAME" | tr -c 'A-Za-z0-9._-' '_')

    echo "[INFO] Acquiring PID $PID ($PROCESS_NAME)..."

    # Create a separate directory for each process
    PROCESS_DIR="${OUTPUT_DIR}/PID_${PID}_${SAFE_NAME}"

    if ! mkdir -p -- "$PROCESS_DIR"; then
        echo "[ERROR] Cannot create directory for PID $PID."
        ((FAILED+=1))
        continue
    fi

    # Record process metadata before acquisition
    {
        echo "PID: $PID"
        echo "Process name: $PROCESS_NAME"
        echo "Acquisition time: $(date --iso-8601=seconds)"
        printf 'Command line: '
        tr '\0' ' ' < "/proc/$PID/cmdline" 2>/dev/null || true
        echo
    } > "${PROCESS_DIR}/process_information.txt"

    # Generate the process core dump
    if gcore -o "${PROCESS_DIR}/core" "$PID"; then
        echo "[SUCCESS] PID $PID acquired."
        ((SUCCESS+=1))
    else
        echo "[ERROR] Failed to acquire PID $PID."
        echo "gcore failed for PID $PID at $(date --iso-8601=seconds)" \
            >> "${PROCESS_DIR}/error.txt"
        ((FAILED+=1))
    fi

    echo
done

# Generate SHA-256 hashes for acquired files
echo "[INFO] Generating SHA-256 manifest..."

(
    cd "$OUTPUT_DIR" || exit 1

    find . -type f \
        ! -name 'sha256_manifest.txt' \
        ! -name 'sha256_manifest.tmp' \
        -print0 |
        sort -z |
        xargs -0 -r sha256sum > sha256_manifest.tmp

    mv sha256_manifest.tmp sha256_manifest.txt
)

HASH_STATUS=$?

# Final acquisition summary
echo
echo "=========================================="
echo " Acquisition Summary"
echo "=========================================="
echo "End time: $(date --iso-8601=seconds)"
echo "Total processes identified: $TOTAL"
echo "Successful acquisitions: $SUCCESS"
echo "Failed acquisitions: $FAILED"
echo "Skipped processes: $SKIPPED"
echo "SHA-256 manifest status: $HASH_STATUS"
echo "Output directory: $OUTPUT_DIR"
echo "Log file: $LOG_FILE"
echo "Hash manifest: $MANIFEST_FILE"
echo "=========================================="

exit 0

