#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "${script_dir}/.." && pwd)

src_dns_ip="${repo_root}/data/dns-ip.csv"
dst_dir="${HOME}/.local/share/pcaptool"
dst_dns_ip="${dst_dir}/dns-ip.csv"

if [[ ! -f "${src_dns_ip}" ]]; then
  echo "source dns-ip.csv not found: ${src_dns_ip}" >&2
  exit 1
fi

cd "${repo_root}"

echo "[1/3] go build ."
go build .

echo "[2/3] go install ."
go install .

echo "[3/3] install dns-ip.csv -> ${dst_dns_ip}"
mkdir -p "${dst_dir}"
cp "${src_dns_ip}" "${dst_dns_ip}"

echo "pcaptool installed"
echo "dns-ip.csv installed at: ${dst_dns_ip}"
