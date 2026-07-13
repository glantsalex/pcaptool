#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

PCAPTOOL_BIN="${SCRIPT_DIR}/pcaptool"
DATA_DIR="${SCRIPT_DIR}/data"

NET_ID="404163-1"
DNS_RULES_FILE="${DATA_DIR}/pcaptool.rules.yaml"
DNS_IP_FILE="${DATA_DIR}/dns-ip.csv"

usage() {
  cat >&2 <<EOF
Usage:
  $SCRIPT_NAME <pcap_directory>

Description:
  Runs pcaptool dnsextract for net-id ${NET_ID} using the supplied PCAP directory.

Example:
  ./$SCRIPT_NAME /home/alex/pcap-data/404163/404163-1/input/2026/07/08
EOF
}

log() {
  printf '[%(%Y-%m-%d %H:%M:%S)T] %s\n' -1 "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

main() {
  if [[ "$#" -ne 1 ]]; then
    usage
    exit 1
  fi

  local pcap_dir="$1"

  [[ -d "$pcap_dir" ]] || die "PCAP directory does not exist or is not a directory: $pcap_dir"
  [[ -x "$PCAPTOOL_BIN" ]] || die "pcaptool not found or not executable: $PCAPTOOL_BIN"
  [[ -f "$DNS_RULES_FILE" ]] || die "DNS normalization rules file not found: $DNS_RULES_FILE"
  [[ -f "$DNS_IP_FILE" ]] || die "DNS IP file not found: $DNS_IP_FILE"

  local -a cmd=(
    "$PCAPTOOL_BIN"
    dnsextract
    -r "$pcap_dir"
    --net-id "$NET_ID"
    --exclude-ports "53,123"
    --enforce-private-as-source
    --ftp-control-ports "21,990,21000"
    --ftp-passive-min-port "10000"
    --server-summary-exclude-udp-ports "33434-33534"
    --dns-normalization-rules "$DNS_RULES_FILE"
    --dns-ip-file "$DNS_IP_FILE"
    --allow-private-dns-donation
    --tls-cert-lookup
  )

  log "Running pcaptool dnsextract"
  log "PCAP directory : $pcap_dir"
  log "Net ID         : $NET_ID"
  log "DNS rules file : $DNS_RULES_FILE"
  log "DNS IP file    : $DNS_IP_FILE"

  echo >&2
  printf 'Command:\n  ' >&2
  printf '%q ' "${cmd[@]}" >&2
  echo >&2
  echo >&2

  "${cmd[@]}"

  log "Completed successfully."
}

main "$@"