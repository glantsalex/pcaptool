# pcaptool

`pcaptool` is an offline PCAP analysis CLI focused on DNS, endpoint attribution, and topology extraction.

It is built for the case where you need machine-readable artifacts from packet captures, not just manual Wireshark inspection. The tool scans PCAPs, correlates DNS answers to observed connections, optionally uses TLS SNI, and emits a stable set of output files that can be consumed by downstream systems.

## What It Is For

Typical use cases:

- build a DNS-to-connection table from a PCAP corpus
- derive an issuer-to-destination network topology matrix
- extract service endpoints for downstream ingestion
- identify unresolved DNS names and unresolved public destination IPs
- append high-confidence IP-to-DNS observations into a local fallback map
- run post-processing hooks after a completed extraction run

`pcaptool` is designed as an offline forensic/analytics tool.
It does not modify the source PCAPs.

## Current Command Surface

Commands currently exposed by the binary:

- `dnsextract`
- `completion`
- `help`

In practice, `dnsextract` is the main processing command.

## Installation

### Build locally

```bash
go build .
```

### Install into your Go bin dir

```bash
go install .
```

### Install binary and default `dns-ip.csv`

The repository includes a helper script:

```bash
./shell/install-pcaptool.sh
```

It performs:

1. `go build .`
2. `go install .`
3. copies `data/dns-ip.csv` to `~/.local/share/pcaptool/dns-ip.csv`

## Quick Start

Minimal run:

```bash
pcaptool dnsextract \
  --net-id 401240-1 \
  --read-dir /path/to/pcaps
```

Typical operational run with CSV fallback and common port exclusions:

```bash
pcaptool dnsextract \
  --net-id 401240-1 \
  --read-dir /path/to/pcaps \
  --dns-ip-file ~/.local/share/pcaptool/dns-ip.csv \
  --exclude-ports 53,123 \
  --enforce-private-as-source
```

Run and invoke a post-hook with the manifest path in `PCAPTOOL_MANIFEST`:

```bash
pcaptool dnsextract \
  --net-id 401240-1 \
  --read-dir /path/to/pcaps \
  --post-hook '/opt/hooks/push-topology'
```

## Input Expectations

`dnsextract` walks `--read-dir` recursively and processes files with these extensions:

- `.pcap`
- `.pcapng`
- `.cap`

The files are processed in sorted path order.

## Output Layout

Every run creates a unique UTC-stamped directory:

```text
<output-root>/<net-id>/<YYYY-MM-DD-HH-mm-ss>/
```

Defaults:

- `--output-root`: `pcaptool_output`
- `--net-id`: required

Example:

```text
pcaptool_output/401240-1/2026-03-22-14-37-12/
```

A run always writes `_run-artifacts.json` in the run directory.
That manifest is the machine-readable contract for downstream tooling.

## Artifacts Produced

The exact set depends on flags and on what was observed in the capture.

### Always produced

#### `dns-table.txt` or `dns-table.json`

The main flattened DNS/connection table.

Contents include:

- request time
- issuer IP or issuer label
- DNS name
- resolved IPv4 addresses
- per-IP source/evidence label
- resolver IP
- correlated destination port

`dns-table.txt` is human-readable tabular output.
`dns-table.json` is structured JSON output selected by `--format json`.

#### `service-endpoints.txt`

Indented JSON array of service endpoint objects derived from topology rows.

Current fields:

- `ip`
- `dns`
- `protocol`
- `port`
- `peers_count`
- `hash_val`
- `observed_at`

Uniqueness key:

- `(ip, dns, protocol, port)`

Special cases:

- public destination with no DNS becomes `"[no-dns-attribution]"`
- non-public destination with no DNS becomes `"[private-server]"`
- if the same `(ip,protocol,port)` has at least one real DNS name, synthetic names are not emitted for that tuple

#### `_run-artifacts.json`

Run manifest with absolute paths and run metadata.

Current top-level fields:

- `run_id`
- `net_id`
- `run_dir`
- `output_root`
- `read_dir`
- `run_started_at_utc`
- `pcap_files_count`
- `main_output_format`
- `first_packet_ts_utc`
- `first_packet_pcap_file`
- `files`

### Usually produced

#### `network-topology-matrix.txt`

Issuer-to-destination connectivity matrix with DNS attribution source.

Columns are effectively:

- issuer
- destination IP
- DNS name
- source/evidence
- protocol
- port

This is the main artifact for reasoning about who talks to what.

#### `network-topology-matrix.json`

Machine-readable JSON sibling of `network-topology-matrix.txt`.

Top-level shape:

- `version`
- `entries`

Each entry includes:

- `issuer_ip`
- `destination_ip`
- `dns_name`
- `dns_source`
- `protocol`
- `port`
- `observed_at_utc`

This file is intended for downstream tooling that should not parse the human-formatted text matrix.

#### `dns-issuer-profile.txt`

Per-issuer DNS activity summary:

- total DNS queries
- unique domains
- unique resolved IPs
- unique connected ports
- connection rate

#### `external-endpoints.txt`

Aggregated endpoint groups by DNS suffix.
Useful as a higher-level service inventory view with:

- dns suffix
- observed DNS names
- sample IPs
- observed `(proto, port)` listeners

### Optional / conditional outputs

#### `dns-unresolved-dns.txt`

Unresolved DNS names that remained unresolved after attribution.
Includes issuer and first PCAP file seen.

#### `unresolved-ip.json`

JSON array of unresolved public destination endpoints that ended up with no DNS attribution in the final topology.
Each entry contains:

- `ip`
- `port`
- `proto`
- `count`

#### `export_csv` target

If `--export-csv` is used, the main records are exported as CSV.
Relative paths are resolved under the run directory.

#### `ip-dns-append-audit.txt`

Produced only when both conditions are true:

- `--dns-ip-file` is set
- `--debug` is set

This records provenance for newly learned CSV rows appended during the run.

#### extra manifest copy

If `--manifest-out` is set, a copy of `_run-artifacts.json` is written to the requested path.

## How `dnsextract` Works

The command is a multi-pass offline pipeline.

### Pass 1: optional RADIUS/IP-to-IMSI index

If `--radius-imsi` is enabled, the PCAP corpus is scanned for RADIUS Accounting records and a time-aware IP-to-IMSI index is built.

This does not change packet correlation itself.
It changes issuer labeling in the final outputs.

### Pass 2: DNS scan and optional TLS SNI scan

The tool scans the corpus and builds `DNSTransaction` objects from:

- DNS responses
- synthetic TLS SNI observations, unless `--disable-sni` is set

This pass is where names and directly parsed DNS answer IPs are collected.

### Pass 2.1: optional NTP-name filtering

By default, the tool removes NTP-like names using a heuristic filter.
This is controlled by `--ignore-ntp`.

### Pass 2.5: optional active resolve

If `--active-resolve` is enabled, unresolved DNS names are resolved against external resolvers.
This is intentionally disabled by default because it is not capture-time truth.

### Pass 3: connection correlation

Observed TCP and UDP connectivity is joined back to transactions.
This is where the tool learns:

- destination port
- transport protocol
- whether a name-to-IP mapping was actually observed in traffic

This pass also uses `--exclude-ports` and `--enforce-private-as-source`.

### Topology build

The final topology matrix is built by joining connectivity edges back to the best DNS/SNI evidence available, with a configurable age window (`--topology-dns-window`).

### Service endpoint build

The topology matrix is then reduced into unique service endpoint tuples for downstream ingestion.

## Attribution Heuristics and Evidence Labels

`pcaptool` is conservative by design: stronger evidence wins over weaker fallback.

Common source labels in `network-topology-matrix.txt` and related outputs:

| Label | Meaning |
|---|---|
| `dns+synack` | direct DNS answer parsed from PCAP and observed connection confirmation |
| `dns+conn+synack` | DNS name came from packet evidence, but the IP was backfilled from observed connectivity because the answer was incomplete or truncated |
| `sni+synack` | name came from TLS SNI and was confirmed by observed connection |
| `sni+conn+synack` | SNI-derived name with connectivity-backed IP inference |
| `active+synack` | name was obtained by active resolver lookup and later confirmed by observed connection |
| `active+conn+synack` | active-resolve name with connectivity-inferred IP |
| `csv+conn` | DNS came from `dns-ip.csv` fallback on a non-mid-session row |
| `csv+mid` | DNS came from `dns-ip.csv` fallback for a mid-session row |
| `mid-session` | connection was observed without usable DNS attribution |
| `peer+ipport` | unresolved row was completed from another issuer in the same run using a unique strong donor on the same `(dstIP, proto, port)` |
| `peer+ipport+conn` | unresolved row was completed from another issuer in the same run using an inferred strong donor on the same `(dstIP, proto, port)` |

Important details:

- CSV fallback never acts as a donor for peer completion.
- Mid-session peer completion is run-local only; it is not persisted back into `dns-ip.csv`.
- Strong direct evidence suppresses weaker conflicting CSV fallback where possible.

## `dns-ip.csv` / `dns-ip.txt` Fallback Map

The `--dns-ip-file` input is a last-resort IP-to-DNS attribution source.
It is useful for truncated captures, shared environments, and repeated stable services.

### Accepted line formats

The loader auto-detects these forms:

- `dns,ip`
- `ip,dns`
- `dns ip`
- `ip dns`

Other rules:

- IPv4 only
- blank lines are ignored
- lines beginning with `#` are ignored
- DNS names are lowercased and trailing dots are trimmed

### Current fallback policy

CSV fallback is intentionally conservative.

- If an IP has exactly one DNS name in the CSV map, full FQDN fallback is allowed.
- If an IP has more than one DNS name in the CSV map, fallback is skipped.
- Existing IPs in the base CSV are not extended with new names.
- Newly learned rows are limited to one representative DNS per unseen public IP.

### Current learning policy

When `--dns-ip-file` is set, `pcaptool` can append new pairs to the file.

Learning is restricted to strong direct evidence:

- previously unseen public IP only
- direct DNS-answer-backed
- observed connection backed
- not connectivity-inferred

In practice, this means pairs equivalent to `dns+synack` are learnable.
Pairs equivalent to `dns+conn+synack` are not persisted.

### Why this matters

This policy is designed to reduce CSV contamination from:

- truncated DNS answers
- shared cloud IPs
- historical or ambiguous multi-name IPs

## Topology Assumptions and Tradeoffs

`pcaptool` is optimized for operationally useful attribution, but it still makes explicit tradeoffs.

### Conservative choices

- strong packet evidence wins over CSV fallback
- multi-name CSV IPs do not fallback
- post-capture active resolve is opt-in only
- learned CSV rows require strong direct DNS evidence

### Practical heuristics

- TLS SNI is used as a synthetic name source unless disabled
- unresolved rows can inherit a name from another issuer in the same run when `(dstIP, proto, port)` uniquely matches a strong donor
- truncated DNS responses are salvaged only up to the last complete answer; incomplete tail answers are ignored

### Known limitations

- captures without DNS and without SNI will still produce `mid-session` rows
- historical cloud/CDN IP reuse can still make attribution ambiguous
- active resolve is not historical truth
- CSV fallback is intentionally incomplete by design when ambiguity is high

## CLI Reference

## Root command flags

| Flag | Type | Default | Meaning |
|---|---|---:|---|
| `--net-id` | string | required | logical network identifier; scopes the output directory |
| `--output-root`, `-o` | string | `pcaptool_output` | root directory for all run output |
| `--enforce-private-as-source` | bool | `false` | for UDP only, if one side is private/local treat it as the source side |

## `dnsextract` flags

| Flag | Type | Default | Meaning |
|---|---|---:|---|
| `--read-dir`, `-r` | string | required | directory containing PCAP files; walked recursively |
| `--format` | string | `table` | main output format: `table` or `json` |
| `--export-csv` | string | empty | optional CSV export path for main records |
| `--short`, `-s` | bool | `false` | squash topology to one row per issuer/DNS/port |
| `--radius-imsi` | bool | `false` | map issuer IPs to IMSI via RADIUS Accounting data |
| `--only-tcp` | bool | `false` | only correlate TCP connections |
| `--ignore-ntp` | bool | `true` | drop NTP-like DNS names using heuristic filtering |
| `--dns-ip-file` | string | empty | path to fallback DNS/IP map used for last-resort attribution |
| `--exclude-ports` | string | `53` | comma-separated destination/server ports to exclude from topology correlation |
| `--active-resolve` | bool | `false` | resolve unresolved names against external resolvers |
| `--active-resolvers` | string | empty | comma-separated resolver IPs for active resolve |
| `--disable-sni` | bool | `false` | skip TLS ClientHello/SNI scan |
| `--unsorted` | bool | `false` | preserve natural first-seen issuer order in topology output |
| `--debug` | bool | `false` | emit additional debug artifacts, including CSV append audit |
| `--manifest-out` | string | empty | write an extra copy of `_run-artifacts.json` |
| `--post-hook` | string array | empty | shell command(s) to run after extraction completes |
| `--topology-dns-window` | duration | `2m` | max age between DNS query and first observed edge for topology attribution |

## Post-hook Contract

If `--post-hook` is used, each hook runs:

- after all output artifacts are written
- with current working directory set to the run directory
- with `PCAPTOOL_MANIFEST` in the environment

`PCAPTOOL_MANIFEST` points to the canonical `_run-artifacts.json` path.

A non-zero hook exit fails the command.

## Helper Scripts Included in This Repo

Repository scripts under `shell/`:

- `shell/install-pcaptool.sh`
  - builds, installs, and installs the default `dns-ip.csv`
- `shell/run-dnsextract-days.sh`
  - GCS-oriented day-by-day wrapper for repeated runs
- `shell/dns_ip_dedup_sort.sh`
  - helper for normalizing the DNS/IP map
- `shell/recover-unresolved-ip-dns.sh`
  - utility to recover unresolved IP-to-DNS pairs by scanning prior run outputs

## Suggested Operational Defaults

A practical default command for mobile/IoT capture corpora is:

```bash
pcaptool dnsextract \
  --net-id <stream-id> \
  --read-dir <pcap-dir> \
  --dns-ip-file ~/.local/share/pcaptool/dns-ip.csv \
  --exclude-ports 53,123 \
  --enforce-private-as-source
```

Reasoning:

- exclude DNS and NTP from service topology by default
- normalize ambiguous UDP directionality
- allow stable CSV fallback and learning where evidence is strong

## License

Apache-2.0
