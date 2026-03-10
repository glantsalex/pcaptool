#!/usr/bin/env bash
set -euo pipefail

# recover-unresolved-ip-dns.sh
#
# Walk a pcaptool output tree and recover DNS,IP pairs for unresolved public IPs
# using existing dns-table.txt files.
#
# Rules:
# - Input: root directory containing run subdirectories
# - Recursively find every unresolved-ip.txt under the root
# - For each IP in each unresolved-ip.txt:
#   1) look in dns-table.txt from the same directory
#   2) if not found there, scan dns-table.txt files under the root in sorted order
#      and stop at the first directory that contains that IP
# - If one matching row exists, use it
# - If multiple rows exist in the chosen dns-table.txt, keep the strongest source
# - Output format: "dns,ip"
# - Output is de-duplicated by exact DNS,IP pair
#
# Source strength ranking:
#   dns+synack > dns+conn+synack > sni+synack > sni+conn+synack >
#   active+synack > active+conn+synack > csv+conn > csv+mid >
#   mid-session > anything else > empty
#
# Usage:
#   ./shell/recover-unresolved-ip-dns.sh /path/to/root [output-file]
#
# Default output file:
#   <root>/recovered-unresolved-ip-dns.txt

usage() {
  echo "Usage: $0 /path/to/output-root [output-file]" >&2
  exit 2
}

show_progress() {
  local stage="$1"
  local current="$2"
  local total="$3"
  local extra="${4:-}"
  if [[ -n "$extra" ]]; then
    printf '\r[%s] %d/%d %s' "$stage" "$current" "$total" "$extra" >&2
  else
    printf '\r[%s] %d/%d' "$stage" "$current" "$total" >&2
  fi
}

trim() {
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

root="${1:-}"
[[ -n "$root" ]] || usage
[[ -d "$root" ]] || { echo "ERROR: root directory not found: $root" >&2; exit 2; }
root="$(cd "$root" && pwd)"

out="${2:-$root/recovered-unresolved-ip-dns.txt}"

tmp_candidates="$(mktemp)"
tmp_pairs="$(mktemp)"
tmp_missing="$(mktemp)"
trap 'rm -f "$tmp_candidates" "$tmp_pairs" "$tmp_missing"' EXIT

mapfile -t dns_tables < <(find "$root" -type f -name 'dns-table.txt' | LC_ALL=C sort)
mapfile -t unresolved_files < <(find "$root" -type f -name 'unresolved-ip.txt' | LC_ALL=C sort)

if [[ ${#unresolved_files[@]} -eq 0 ]]; then
  echo "ERROR: no unresolved-ip.txt files found under $root" >&2
  exit 1
fi

total_unresolved_files=${#unresolved_files[@]}
total_dns_tables=${#dns_tables[@]}
total_ips=0
for uf in "${unresolved_files[@]}"; do
  count="$(
    awk '
      {
        line=$0
        sub(/^[ \t\r\n]+/, "", line)
        sub(/[ \t\r\n]+$/, "", line)
        if (line == "" || line ~ /^#/) next
        c++
      }
      END { print c + 0 }
    ' "$uf"
  )"
  total_ips=$((total_ips + count))
done

# Flatten all dns-table.txt rows into:
# dir \t ip \t dns \t source \t rank \t seq
dns_idx=0
for table in "${dns_tables[@]}"; do
  dns_idx=$((dns_idx + 1))
  show_progress "Index dns-table.txt" "$dns_idx" "$total_dns_tables"
  dir="$(dirname "$table")"
  awk -F'|' -v DIR="$dir" '
    function trim(s) {
      gsub(/^[ \t\r\n]+/, "", s)
      gsub(/[ \t\r\n]+$/, "", s)
      return s
    }
    function rank(src, s) {
      s = tolower(trim(src))
      if (s == "dns+synack") return 100
      if (s == "dns+conn+synack") return 90
      if (s == "sni+synack") return 80
      if (s == "sni+conn+synack") return 70
      if (s == "active+synack") return 60
      if (s == "active+conn+synack") return 50
      if (s == "csv+conn") return 40
      if (s == "csv+mid") return 30
      if (s == "mid-session") return 20
      if (s != "") return 10
      return 0
    }
    BEGIN {
      lastDNS = ""
      seq = 0
    }
    /^\|[-|[:space:]]+\|$/ { next }
    $0 !~ /^\|/ { next }
    {
      req = trim($2)
      dns = trim($4)
      ip  = trim($5)
      src = trim($6)

      if (tolower(req) == "request time") next

      if (dns != "") {
        lastDNS = dns
      } else {
        dns = lastDNS
      }

      if (dns == "" || ip == "") next

      seq++
      print DIR "\t" ip "\t" dns "\t" src "\t" rank(src) "\t" seq
    }
  ' "$table" >> "$tmp_candidates"
done
if (( total_dns_tables > 0 )); then
  printf '\n' >&2
fi

pick_best_in_dir() {
  local dir="$1"
  local ip="$2"
  awk -F'\t' -v DIR="$dir" -v IP="$ip" '
    $1 == DIR && $2 == IP {
      r = $5 + 0
      s = $6 + 0
      if (!found || r > bestRank || (r == bestRank && s < bestSeq)) {
        found = 1
        bestDNS = $3
        bestRank = r
        bestSeq = s
      }
    }
    END {
      if (found) print bestDNS
    }
  ' "$tmp_candidates"
}

pick_best_global_first_dir() {
  local ip="$1"
  awk -F'\t' -v IP="$ip" '
    $2 != IP { next }
    {
      if (targetDir == "") targetDir = $1
      if ($1 != targetDir) exit

      r = $5 + 0
      s = $6 + 0
      if (!found || r > bestRank || (r == bestRank && s < bestSeq)) {
        found = 1
        bestDNS = $3
        bestRank = r
        bestSeq = s
      }
    }
    END {
      if (found) print bestDNS
    }
  ' "$tmp_candidates"
}

processed_ips=0
resolved_local=0
resolved_global=0
unresolved_still=0
processed_files=0

for uf in "${unresolved_files[@]}"; do
  processed_files=$((processed_files + 1))
  dir="$(dirname "$uf")"
  while IFS= read -r raw || [[ -n "$raw" ]]; do
    ip="$(trim "$raw")"
    [[ -n "$ip" ]] || continue
    [[ "$ip" == \#* ]] && continue
    processed_ips=$((processed_ips + 1))

    dns="$(pick_best_in_dir "$dir" "$ip")"
    if [[ -n "$dns" ]]; then
      printf '%s,%s\n' "$dns" "$ip" >> "$tmp_pairs"
      resolved_local=$((resolved_local + 1))
      show_progress "Recover unresolved IPs" "$processed_ips" "$total_ips" \
        "files=${processed_files}/${total_unresolved_files} local=${resolved_local} root=${resolved_global} missing=${unresolved_still}"
      continue
    fi

    dns="$(pick_best_global_first_dir "$ip")"
    if [[ -n "$dns" ]]; then
      printf '%s,%s\n' "$dns" "$ip" >> "$tmp_pairs"
      resolved_global=$((resolved_global + 1))
      show_progress "Recover unresolved IPs" "$processed_ips" "$total_ips" \
        "files=${processed_files}/${total_unresolved_files} local=${resolved_local} root=${resolved_global} missing=${unresolved_still}"
      continue
    fi

    printf '%s\n' "$ip" >> "$tmp_missing"
    unresolved_still=$((unresolved_still + 1))
    show_progress "Recover unresolved IPs" "$processed_ips" "$total_ips" \
      "files=${processed_files}/${total_unresolved_files} local=${resolved_local} root=${resolved_global} missing=${unresolved_still}"
  done < "$uf"
done

if (( total_ips > 0 )); then
  printf '\n' >&2
fi

mkdir -p "$(dirname "$out")"
LC_ALL=C sort -u "$tmp_pairs" > "$out"

echo "Wrote: $out"
echo "Processed unresolved IP rows: $processed_ips"
echo "Recovered from same directory: $resolved_local"
echo "Recovered from root scan: $resolved_global"
echo "Still unresolved: $unresolved_still"
