#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage:
  run-dnsextract-days.sh [--dry-run] <stream-id> <year> <month> <day>

Behavior:
  - Starts at YYYY-MM-DD and iterates day-by-day
  - For each day:
      1) list+filter day PCAPs in GCS (same semantics as gcs-copy-24.sh)
      2) download in chunks of 20 via gsutil -m cp
      3) run: sudo ./pcaptool dnsextract -r <local_dir> --net-id <stream-id> --exclude-ports 53,123 --dns-ip-file ./data/ip-dns.txt
      4) delete copied PCAPs
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

  # Remove any leftover chunk files
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
command -v split  >/dev/null 2>&1 || { echo "Error: split not found" >&2; exit 1; }
[[ -x "$PCAPTOOL" ]]    || { echo "Error: $PCAPTOOL not found/executable" >&2; exit 1; }
[[ -f "$DNS_IP_FILE" ]] || { echo "Error: $DNS_IP_FILE not found" >&2; exit 1; }

# Build paths for a given date (matches gcs-copy-24.sh layout)
gcs_base_path() {
  local y="$1" m="$2" d="$3"
  echo "${BUCKET}/${STREAM}/${STREAM}-1/input/${y}/${m}/${d}"
}
local_base_path() {
  local y="$1" m="$2" d="$3"
  echo "${SCRIPT_DIR}/${STREAM}/${STREAM}-1/input/${y}/${m}/${d}"
}

# List all .pcap objects and apply the same filter intent as gcs-copy-24.sh:
#   - keep files that end with a01.pcap
#   - OR keep files that do NOT contain "a01" anywhere in the name
#
# gcs-copy-24.sh uses a grep negative lookahead that isn't portable.
# This awk implements the same semantics reliably.
list_matching_pcaps() {
  local base="$1"
  # If ls fails (e.g., no files), return empty list without erroring the script.
  gsutil ls "${base}/*.pcap" 2>/dev/null \
    | awk '($0 ~ /a01\.pcap$/) || ($0 !~ /a01/)' \
    || true
}

# Download the given newline-separated list of GCS URLs into LOCAL_DIR
# - full mode: split into chunks of 20 and gsutil -m cp each chunk (same as gcs-copy-24.sh)
# - dry-run: download only first 5 objects
download_pcaps() {
  local local_dir="$1"
  local files="$2"

  mkdir -p "$local_dir"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "Dry-run: downloading only 5 files..."

    # Collect first 5 lines without pipelines (avoids SIGPIPE under pipefail)
    local first5=()
    while IFS= read -r obj; do
      [[ -n "$obj" ]] || continue
      first5+=( "$obj" )
      [[ ${#first5[@]} -ge 5 ]] && break
    done <<< "$files"

    if [[ ${#first5[@]} -eq 0 ]]; then
      return 0
    fi

    gsutil -m cp "${first5[@]}" "$local_dir/"

    # CRITICAL: stop here; do NOT continue to full download
    return 0
  fi

  # Full mode: split into chunks of 20 and download each chunk
  echo "$files" | split -l 20 - "gcs_chunk_"

  shopt -s nullglob
  for chunk in gcs_chunk_*; do
    echo "Downloading chunk: $chunk"
    gsutil -m cp $(cat "$chunk") "$local_dir/"
    rm -f "$chunk"
  done
  shopt -u nullglob

  echo "✅ All matching .pcap files downloaded to: $local_dir"
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
  echo "Scanning for files in: $BASE"
  echo "Local dest: $LOCAL_DIR"

  FILES="$(list_matching_pcaps "$BASE")"
  if [[ -z "$FILES" ]]; then
    echo "No matching .pcap files found in ${BASE} -> stopping."
    break
  fi

  download_pcaps "$LOCAL_DIR" "$FILES"

  # Verify we actually have pcaps locally; if not, stop (defensive)
  if ! find "$LOCAL_DIR" -maxdepth 1 -type f -name '*.pcap' | grep -q .; then
    echo "No local .pcap files found in $LOCAL_DIR after download -> stopping."
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