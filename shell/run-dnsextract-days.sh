#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage:
  run-dnsextract-days.sh [--dry-run] <stream-id> <year> <month> <day>

Behavior:
  - Starts at YYYY-MM-DD and iterates day-by-day
  - For each day:
      1) copy pcaps from GCS (calls ./gcs-copy-24.sh)
      2) run: sudo ./pcaptool dnsextract -r <local_dir> --net-id <stream-id> --exclude-ports 53,123 --dns-ip-file ./data/ip-dns.txt
      3) delete copied pcaps
  - Stops when a day has no matching .pcap objects.

--dry-run:
  Copies ONLY 5 files per day (still runs dnsextract and deletes copied pcaps).
EOF
  exit 1
}

DRY_RUN=0
if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=1
  shift
fi

[[ $# -eq 4 ]] || usage

STREAM="$1"
YEAR="$2"
MONTH="$3"
DAY="$4"

# Normalize month/day to 2 digits (02, 03, ...)
MONTH="$(printf '%02d' "$MONTH")"
DAY="$(printf '%02d' "$DAY")"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

COPY_SCRIPT="$SCRIPT_DIR/gcs-copy-24.sh"
PCAPTOOL="$SCRIPT_DIR/pcaptool"
DNS_IP_FILE="$SCRIPT_DIR/data/ip-dns.txt"

BUCKET="gs://pulse-wl-input"

# ---- Trap-based cleanup ----
CURRENT_LOCAL_DIR=""
cleanup() {
  local rc=$?
  if [[ $rc -ne 0 ]]; then
    echo "!! wrapper exiting with code=$rc; cleaning up temporary artifacts..." >&2
  fi

  # Remove any leftover chunk files created by gcs-copy-24.sh
  rm -f "$SCRIPT_DIR"/gcs_chunk_* 2>/dev/null || true

  # Remove current day's copied PCAPs dir (if set and exists)
  if [[ -n "${CURRENT_LOCAL_DIR}" && -d "${CURRENT_LOCAL_DIR}" ]]; then
    rm -rf "${CURRENT_LOCAL_DIR}" 2>/dev/null || true
  fi

  exit $rc
}
trap cleanup EXIT INT TERM

# Sanity checks
command -v gsutil >/dev/null 2>&1 || { echo "Error: gsutil not found" >&2; exit 1; }
command -v date   >/dev/null 2>&1 || { echo "Error: date not found" >&2; exit 1; }
[[ -x "$COPY_SCRIPT" ]] || { echo "Error: $COPY_SCRIPT not found/executable" >&2; exit 1; }
[[ -x "$PCAPTOOL" ]]    || { echo "Error: $PCAPTOOL not found/executable" >&2; exit 1; }
[[ -f "$DNS_IP_FILE" ]] || { echo "Error: $DNS_IP_FILE not found" >&2; exit 1; }

# Helper: build paths for a given date
gcs_base_path() {
  local y="$1" m="$2" d="$3"
  echo "${BUCKET}/${STREAM}/${STREAM}-1/input/${y}/${m}/${d}"
}
local_base_path() {
  local y="$1" m="$2" d="$3"
  # Must match gcs-copy-24.sh LOCAL_BASE convention
  echo "${SCRIPT_DIR}/${STREAM}/${STREAM}-1/input/${y}/${m}/${d}"
}

# Helper: list "matching" pcaps in GCS for a given day.
# keep file if it ends with a01.pcap OR does NOT contain 'a01' anywhere.
list_matching_pcaps() {
  local base="$1"
  gsutil ls "${base}/*.pcap" 2>/dev/null \
    | awk '($0 ~ /a01\.pcap$/) || ($0 !~ /a01/)' \
    || true
}

cur="${YEAR}-${MONTH}-${DAY}"

echo "Wrapper starting at: $cur"
echo "Stream-id: $STREAM"
echo "Dry-run: $DRY_RUN"
echo

while true; do
  y="${cur:0:4}"
  m="${cur:5:2}"
  d="${cur:8:2}"

  BASE="$(gcs_base_path "$y" "$m" "$d")"
  LOCAL_DIR="$(local_base_path "$y" "$m" "$d")"
  CURRENT_LOCAL_DIR="$LOCAL_DIR"

  echo "=== Day: $cur ==="
  echo "GCS:   $BASE"
  echo "Local: $LOCAL_DIR"

  FILES="$(list_matching_pcaps "$BASE")"
  if [[ -z "$FILES" ]]; then
    echo "No matching .pcap files in $BASE -> stopping."
    break
  fi

  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "Dry-run: copying only 5 files..."
    mkdir -p "$LOCAL_DIR"
    echo "$FILES" | head -n 5 | while read -r obj; do
      [[ -n "$obj" ]] || continue
      echo "  gsutil cp $obj -> $LOCAL_DIR/"
      gsutil cp "$obj" "$LOCAL_DIR/"
    done
  else
    echo "Copying full day via: $COPY_SCRIPT $STREAM $y $m $d"
    "$COPY_SCRIPT" "$STREAM" "$y" "$m" "$d"
  fi

  # Verify we actually have pcaps locally; if not, stop (defensive)
  if ! find "$LOCAL_DIR" -maxdepth 1 -type f -name '*.pcap' | grep -q .; then
    echo "No local .pcap files found in $LOCAL_DIR after copy -> stopping."
    break
  fi

  echo "Running dnsextract..."
  sudo "$PCAPTOOL" dnsextract \
    -r "$LOCAL_DIR" \
    --net-id "$STREAM" \
    --exclude-ports 53,123 \
    --dns-ip-file "$DNS_IP_FILE"

  echo "dnsextract done. Deleting copied pcaps: $LOCAL_DIR"
  rm -rf "$LOCAL_DIR"
  CURRENT_LOCAL_DIR=""

  # Next day
  cur="$(date -d "${cur} +1 day" +%Y-%m-%d)"
  echo
done

echo "DONE."