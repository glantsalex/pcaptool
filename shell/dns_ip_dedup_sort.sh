#!/usr/bin/env bash
set -euo pipefail

# dns_ip_dedup_sort.sh
#
# Input:  file with lines like "dns,ip"
# Output (next to the input file by default):
#   1) dns-ip-sorted.txt          (sorted by DNS, then IP)   format: "dns,ip"
#   2) ip-dns-sorted.txt          (sorted by IP, then DNS)   format: "ip,dns"
#   3) ip-multi-dns-sorted.txt    IPs that map to >1 DNS     format: "ip,count,dns1|dns2|..."
#
# Rules:
# - Input file is NEVER modified (read-only processing)
# - Empty / whitespace-only lines are ignored
# - Lines that (after leading whitespace) begin with "#" or "-" are copied "as is" into ALL outputs
# - Duplicate DNS,IP pairs are removed (DNS normalized to lowercase, trailing '.' removed; IP trimmed)
#
# Optional:
#   OUT_DIR=/some/dir ./dns_ip_dedup_sort.sh /path/to/input.txt

usage() {
  echo "Usage: $0 /path/to/dns_ip_pairs.txt" >&2
  exit 2
}

in="${1:-}"
[[ -n "$in" ]] || usage
[[ -f "$in" ]] || { echo "ERROR: input file not found: $in" >&2; exit 2; }

out_dir="${OUT_DIR:-$(dirname "$in")}"
dns_out="${out_dir}/dns-ip-sorted.txt"
ip_out="${out_dir}/ip-dns-sorted.txt"
ip_multi_out="${out_dir}/ip-multi-dns-sorted.txt"

tmp_pairs="$(mktemp)"   # dns,ip (deduped)
tmp_misc="$(mktemp)"    # pass-through lines (# / - / malformed)
tmp_ipdns="$(mktemp)"   # ip,dns (sorted)
trap 'rm -f "$tmp_pairs" "$tmp_misc" "$tmp_ipdns"' EXIT

awk -v PAIRS="$tmp_pairs" -v MISC="$tmp_misc" '
function ltrim(s){ sub(/^[ \t\r\n]+/, "", s); return s }
function rtrim(s){ sub(/[ \t\r\n]+$/, "", s); return s }
function trim(s){ return rtrim(ltrim(s)) }

{
  line = $0
  t = line
  sub(/^[ \t]+/, "", t)

  # ignore empty/whitespace lines
  if (t ~ /^[ \t\r\n]*$/) next

  # pass-through comment lines (starting with # or - after leading whitespace)
  if (t ~ /^[#-]/) { print line >> MISC; next }

  # must contain a comma
  c = index(line, ",")
  if (c == 0) { print line >> MISC; next }

  dns = trim(substr(line, 1, c-1))
  ip  = trim(substr(line, c+1))

  # if malformed, keep as-is
  if (dns == "" || ip == "") { print line >> MISC; next }

  # normalize DNS for dedup/sort stability
  dns = tolower(dns)
  sub(/\.$/, "", dns) # strip trailing dot

  key = dns SUBSEP ip
  if (!(key in seen)) {
    seen[key] = 1
    print dns "," ip >> PAIRS
  }
}
' "$in"

# 1) dns-ip-sorted.txt: misc first, then sorted pairs
{
  cat "$tmp_misc"
  [[ -s "$tmp_misc" && -s "$tmp_pairs" ]] && echo
  LC_ALL=C sort -t',' -k1,1 -k2,2V "$tmp_pairs"
} > "$dns_out"

# 2) ip-dns-sorted.txt: misc first, then sorted pairs as "ip,dns"
{
  cat "$tmp_misc"
  [[ -s "$tmp_misc" && -s "$tmp_pairs" ]] && echo
  awk -F',' '{print $2 "," $1}' "$tmp_pairs" | LC_ALL=C sort -t',' -k1,1V -k2,2
} > "$ip_out"

# Build ip,dns sorted (used by #3)
awk -F',' '{print $2 "," $1}' "$tmp_pairs" | LC_ALL=C sort -t',' -k1,1V -k2,2 > "$tmp_ipdns"

# 3) ip-multi-dns-sorted.txt: misc first, then only IPs that map to >1 DNS
# Format: ip,count,dns1|dns2|...
{
  cat "$tmp_misc"
  [[ -s "$tmp_misc" && -s "$tmp_ipdns" ]] && echo
  awk -F',' '
  function flush() {
    if (count > 1) {
      print cur "," count "," list
    }
  }
  {
    ip=$1; dns=$2
    if (NR == 1) {
      cur=ip; list=dns; count=1; lastdns=dns
      next
    }
    if (ip == cur) {
      if (dns != lastdns) {
        list = list "|" dns
        count++
        lastdns = dns
      }
    } else {
      flush()
      cur=ip; list=dns; count=1; lastdns=dns
    }
  }
  END {
    if (NR > 0) flush()
  }' "$tmp_ipdns"
} > "$ip_multi_out"

echo "Input kept intact: $in"
echo "Wrote:"
echo "  $dns_out"
echo "  $ip_out"
echo "  $ip_multi_out"