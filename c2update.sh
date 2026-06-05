#!/bin/bash
# c2update.sh — Wrapper script to update C2IntelFeeds JSON feed.
#
# Usage:
#   ./c2update.sh                              # update all feeds
#   ./c2update.sh -30day                       # update only 30-day active IPs
#   ./c2update.sh -domain                      # update only domain feed
#   ./c2update.sh -output /path/to/feed.json   # custom output path
#   ./c2update.sh -timeout 30                  # custom HTTP timeout
#
# Schedule with cron:
#   0 */6 * * * /path/to/c2update.sh -output /path/to/c2intel_feeds.json >> /var/log/c2update.log 2>&1

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="${SCRIPT_DIR}/c2update/c2update"
OUTPUT="${SCRIPT_DIR}/c2intel_feeds.json"
LOG_FILE="${SCRIPT_DIR}/c2update.log"

# Parse arguments that should pass through to the binary
ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -output)
      OUTPUT="$2"
      shift 2
      ;;
    -30day|-domain|-ipport|-timeout)
      ARGS+=("$1")
      if [[ "$1" == "-timeout" ]]; then
        ARGS+=("$2")
        shift 2
      else
        shift
      fi
      ;;
    *)
      ARGS+=("$1")
      shift
      ;;
  esac
done

echo "[$(date -u '+%Y-%m-%d %H:%M:%S UTC')] Starting C2IntelFeeds update..." | tee -a "$LOG_FILE"

if [ ! -f "$BINARY" ]; then
  echo "ERROR: c2update binary not found at $BINARY" | tee -a "$LOG_FILE"
  echo "Build it with: cd c2update && go build -o c2update ." | tee -a "$LOG_FILE"
  exit 1
fi

if "$BINARY" -output "$OUTPUT" "${ARGS[@]}" 2>&1 | tee -a "$LOG_FILE"; then
  echo "[$(date -u '+%Y-%m-%d %H:%M:%S UTC')] Update complete." | tee -a "$LOG_FILE"
else
  echo "[$(date -u '+%Y-%m-%d %H:%M:%S UTC')] Update FAILED." | tee -a "$LOG_FILE"
  exit 1
fi
