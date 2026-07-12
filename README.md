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

Every run is grouped by the earliest packet's UTC capture date and a UTC run-start timestamp:

```text
<output-root>/<net-id>/pcap-date-YYYY-MM-DD/run-YYYYMMDDTHHMMSSZ/
```

If no packet timestamp is available, the date segment is `pcap-date-unknown`.

Defaults:

- `--output-root`: `pcaptool_output`
- `--net-id`: required

Example:

```text
pcaptool_output/401240-1/pcap-date-2026-06-23/run-20260702T143522Z/
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
- `pcap_date`
- `output_dir` (same final run directory as `run_dir`)
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
- `observed_dns_name` (only when a DNS normalization rule changed the row)
- `normalized_dns_name` (only when a DNS normalization rule changed the row)
- `normalization_rule_id` (only when a DNS normalization rule changed the row)
- `protocol`
- `port`
- `observed_at_utc`

This file is intended for downstream tooling that should not parse the human-formatted text matrix.

#### `unique-dns-port-proto.csv`

Deterministic CSV derived from the final network topology matrix. It contains
one row for every unique `(DNS, port, protocol)` tuple, with columns:

- `dns`
- `port`
- `protocol`

#### `dns-normalization-audit.csv`

Produced only when `--dns-normalization-rules` is set and at least one topology
row is normalized. Manifest key: `dns_normalization_audit`.

Columns:

- `net_id`
- `rule_id`
- `issuer_ip`
- `destination_ip`
- `protocol`
- `port`
- `observed_dns`
- `normalized_dns`
- `original_source`
- `normalized_source`
- `cname_required`
- `cname_matched`
- `cname_chain`

The text topology matrix shows only the effective DNS name. The JSON topology
matrix additionally preserves the observed DNS name, normalized DNS name, and
normalization rule id for normalized rows.

The tuple reflects final matrix attribution after enabled completion steps have
run. An unresolved matrix name is represented by an empty `dns` field. If the
final matrix is empty, the artifact contains only its header.

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

Packet-observed complete DNS names that remain unresolved after final topology attribution, including optional active matrix completion and DNS donation.
Includes issuer and first PCAP file seen.

#### `unresolved-ip.json`

JSON array of unresolved public destination endpoints that ended up with no DNS attribution in the final topology.
Each entry contains:

- `ip`
- `port`
- `proto`
- `count`

#### `active-resolve-log.csv`

Produced whenever `--active-resolve` is enabled, including as a header-only
artifact when there are no candidate names. Manifest key: `active_resolve_log`.

The log contains one deterministic row per canonical name offered to active
resolution:

```text
dns_name,status,configured_resolvers,timeout_seconds,ipv4_answers,matrix_ips,matrix_rows_completed,error
```

Statuses are `resolved`, `no_ipv4`, `timeout`, `error`, or `skipped_invalid`.
`matrix_ips` contains returned IPv4 addresses also present in the matrix, while
`matrix_rows_completed` reports how many rows actually received
`active+matrix`. The resolver column records configured resolvers, not a claimed
per-query responder, because the resolver pool does not expose that provenance.

#### `reverse-dns-lookup-log.csv`

Produced whenever `--reverse-dns-lookup` is enabled, including as a header-only artifact when there are no eligible public IPv4 topology rows. Manifest key: `reverse_dns_lookup_log`.

The log contains one deterministic row per queried IP with these columns:

```text
ip,status,raw_ptr,normalized_name,source,reason,forward_confirmed,forward_ips,error
```

PTR and forward-IP lists are canonicalized, sorted, deduplicated, and joined with semicolons. Individual lookup failures are recorded without failing the run; parent cancellation still aborts the command.

#### `tls-cert-lookup-log.csv`

Produced whenever `--tls-cert-lookup` is enabled, including as a header-only artifact when no eligible endpoints exist. Manifest key: `tls_cert_lookup_log`.

The log contains one deterministic row per unique public IPv4 TCP endpoint actually probed for a strictly unattributed topology row:

```text
ip,port,status,selected_name,reason,subject_cn,dns_sans,issuer_common_name,not_before,not_after,error,source
```

Eligible rows have an empty DNS name, an empty or `mid-session` source, a nonzero port, normalized TCP protocol, and a public IPv4 destination. Each row first probes its exact port, then falls back to `443` and `8443` without duplicating a port already attempted. Probing stops at the first endpoint whose certificate yields a usable selected name; a certificate with no usable SAN or CN does not stop fallback. Exact IP-and-port attempts are shared across rows, while each unique attempt retains its own timeout.

The probe connects by IP without SNI, records only the presented leaf certificate, and uses a bounded worker pool. The default timeout is 15 seconds per endpoint and covers both TCP connection establishment and TLS certificate handshake; `--tls-cert-lookup-timeout` accepts integer values from 5 through 30 seconds. SANs are canonicalized but retained in certificate order, including duplicates and rejected names, so first-choice provenance remains visible. The first usable non-wildcard SAN is selected; a valid leading `*.` wildcard is stripped to its base name. If no SAN is usable, a valid non-wildcard subject CN may be selected. Certificate verification is intentionally disabled because this is diagnostic collection, not authentication.

Selected certificate labels from the row's exact port use source `tls-cert-san+matrix`; labels selected from port `443` or `8443` fallback use `tls-cert-san+matrix-fallback`. Existing attribution is never overwritten. This weak endpoint decoration appears in topology and derived endpoint outputs, but it is not observed DNS evidence, cannot donate to other rows, and is not persisted to DNS transactions or `dns-ip.csv`. Presented certificates describe probe-time endpoint state and are not capture-time truth.

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

#### TCP SYN trail sidecar artifacts

Produced only when `--fleet <path>` is set.

`--fleet` points to a fleet IPv4 list:

- one IPv4 address per line
- blank lines are ignored
- lines beginning with `#` are ignored
- malformed IPv4 entries are errors
- IPv6 entries are errors

The SYN trail is packet-level initiator evidence from raw IPv4 TCP SYN packets.
It is sidecar-only:

- it does not change DNS attribution
- it does not change topology matrix output
- it does not change service-endpoints output
- it does not change connection inference
- `--exclude-ports` does not apply to SYN evidence artifacts

The always-on fleet files are:

- `public-servers-unique.csv`
- `private-servers-unique.csv`
- `private-probes-unique.csv`
- `flow-direction-correction.sql`

With `--debug`, the sidecar additionally writes these detailed artifacts:

- `fleet-to-public-trail.csv`
- `fleet-to-private-nonfleet-trail.csv`
- `fleet-to-public-unique.csv`
- `fleet-to-private-nonfleet-syn-unique.csv`
- `fleet-to-fleet-tcp-syn-trail.csv`
- `fleet-to-fleet-tcp-syn-unique.csv`
- `private-nonfleet-to-fleet-trail.csv`
- `private-nonfleet-to-fleet-tcp-syn-unique.csv`

`private-probes-unique.csv` and manifest key `private_probes_unique` replace the former `private-probes-syn-unique.csv` and `private_probes_syn_unique` names. The probe artifact remains always-on whenever the fleet sidecar runs; the rename does not change its row semantics.

Bucket meanings:

- fleet to public
  - `src_ip` is in fleet
  - `dst_ip` is public / not private-local
  - always-on manifest key: `public_servers_unique`
  - debug manifest keys include: `fleet_to_public_trail`, `fleet_to_public_unique`
- fleet to private non-fleet
  - `src_ip` is in fleet
  - `dst_ip` is private/local
  - `dst_ip` is not in fleet
  - debug manifest keys include: `fleet_to_private_nonfleet_trail`, `fleet_to_private_nonfleet_syn_unique`
- private server unique summary
  - `private-servers-unique.csv` contains unique `dst_ip,dst_port,protocol` rows from the fleet-to-private-nonfleet split
  - TCP rows and non-excluded UDP rows are retained
  - TCP passive FTP data ports are suppressed only when a matching control connection is observed
  - configured UDP destination ports are suppressed only from server summary artifacts
  - manifest key: `private_servers_unique`
- flow direction correction SQL
  - `flow-direction-correction.sql` is generated only; pcaptool does not execute BigQuery
  - manifest key: `flow_direction_correction_sql`
  - SQL keeps `{{gcp_project_id}}` and `{{bq_dataset}}` placeholders literal
  - source table: `flow-data-{net-id}`
  - materialized view: `mv-flow-data-{net-id}`
  - private-server correction rules use the same cleaned `dst_ip,dst_port,protocol` semantics as `private-servers-unique.csv`
  - the final materialized-view schema remains compatible with the flow table projection and does not include `swap_reason`
- fleet to non-fleet unique
  - `fleet-to-public-unique.csv` and `fleet-to-private-nonfleet-syn-unique.csv` summarize fleet-to-non-fleet destinations by locality and protocol scope
- fleet to fleet
  - `src_ip` is in fleet
  - `dst_ip` is in fleet
  - high-interest evidence because SIM-to-SIM communication should normally not happen
- private non-fleet to fleet
  - `src_ip` is private/local
  - `src_ip` is not in fleet
  - `dst_ip` is in fleet

Trail files use this header:

```text
src_ip,dst_ip,dst_port,syn_timestamp_utc
```

Unique files use this header:

```text
src_ip,dst_ip,dst_port
```

`syn_timestamp_utc` uses this format:

```text
2006-01-02 15:04:05.000
```

Timestamp rules:

- UTC
- millisecond precision

## How `dnsextract` Works

The command is a multi-pass offline pipeline.

### Optional TCP SYN trail sidecar

If `--fleet` is set, the PCAP corpus is also scanned for packet-level IPv4 TCP SYN evidence and UDP edge evidence. Server summaries, private probes, and `flow-direction-correction.sql` are always written; detailed trail and unique evidence artifacts require `--debug`. Debug selection changes only artifact writing and does not rescan the corpus. By default, `--fleet-scan-workers 0` auto-selects `min(GOMAXPROCS, file_count)` workers with a minimum of `1`; `--fleet-scan-workers 1` forces sequential scanning, and values greater than `1` force that many concurrent file scanners. Higher values can reduce wall-clock time on large directories but increase disk and CPU pressure. The generated BigQuery script creates a flow-direction-corrected materialized view from `flow-data-{net-id}` into `mv-flow-data-{net-id}` after replacing the `{{gcp_project_id}}` and `{{bq_dataset}}` placeholders.

This sidecar does not feed DNS attribution, connection inference, topology generation, or service endpoint generation.
The SQL script is not executed by pcaptool.

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

If `--active-resolve` is enabled, every name unresolved before active completion is offered to the configured external resolvers. Successful results may complete otherwise unattributed topology rows; names actually attributed in the final topology are then omitted from `dns-unresolved-dns.txt`.
Lookup outcomes and matrix application counts are recorded in `active-resolve-log.csv`.
This is intentionally disabled by default because it is not capture-time truth.

### Pass 3: connection correlation

Observed TCP and UDP connectivity is joined back to transactions.
This is where the tool learns:

- destination port
- transport protocol
- whether a name-to-IP mapping was actually observed in traffic

This pass also uses `--exclude-ports` and `--enforce-private-as-source`.
By default, DNS names are attached to connections only when packet evidence
contains an exact DNS/SNI name-to-destination mapping. The older issuer-only
query/connection timing fallback is available only with
`--infer-dns-from-connections`.

Passive FTP data-edge suppression recognizes control channels on `--ftp-control-ports`.
The default is `21,990`. Syntax is a strict, non-empty comma-separated list of ports in the range `1..65535`; empty entries are rejected. The supplied value replaces the default set and affects only passive FTP/FTPS edge suppression.

Examples:

- `--ftp-control-ports 21,990,21000` adds a custom control port while retaining the defaults.
- `--ftp-control-ports 21000` recognizes only port `21000` as an FTP control port.

The heuristic high-port cutoff is controlled by `--ftp-passive-min-port` and defaults to `30000`. It accepts one port in the range `1..65535`. After a configured FTP control channel is observed for an issuer/server pair, TCP destination ports at or above this value are suppressed as passive data edges. Exact ports announced by PASV/EPSV replies are still suppressed even when they are below the configured cutoff.

For a network with a non-standard control channel and lower passive data range, use `--ftp-control-ports 21,990,21000 --ftp-passive-min-port 10000`.

The two server summary artifacts, `public-servers-unique.csv` and `private-servers-unique.csv`, also suppress explicitly identified UDP destination ports configured by `--server-summary-exclude-udp-ports`. The default is the inclusive traceroute range `33434-33534`. The value accepts strict comma-separated ports and inclusive ranges such as `53,33434-33534`; malformed, empty, reversed, and out-of-range entries are errors. Set the flag to an empty value to disable this suppression.

This UDP filter runs after passive FTP suppression and applies only to the two server summaries. Trail artifacts and edge-unique artifacts retain the original rows. TCP rows on the configured ports are retained, and records with an empty protocol are treated as TCP rather than UDP.

Examples:

- `--server-summary-exclude-udp-ports 33434-33534`
- `--server-summary-exclude-udp-ports 33434-33534,40000,45000-45100`
- `--server-summary-exclude-udp-ports ""`

### Topology build

The final topology matrix is built by joining connectivity edges back to the best DNS/SNI evidence available, with a configurable age window (`--topology-dns-window`).

When `--reverse-dns-lookup` is enabled, PTR lookup runs after active completion and DNS donation as a last-resort pass over still-unattributed public IPv4 matrix rows. Lookup work is bounded, deduplicated by IP, and uses a two-second timeout per IP. A unique forward-confirmed PTR is preferred, followed by a unique usable raw PTR, then a matching AWS EC2 IP-encoded normalization. Ambiguous, local, reverse-zone, invalid, or mismatched AWS names do not fill topology rows. PTR completion is weak endpoint labeling based on current resolver state; it is not observed DNS evidence and does not establish capture-time truth. PTR-completed names cannot act as donation sources and do not alter `dns-unresolved-dns.txt`.

### Service endpoint build

The topology matrix is then reduced into unique service endpoint tuples for downstream ingestion.

## Attribution Heuristics and Evidence Labels

`pcaptool` is conservative by design: stronger evidence wins over weaker fallback.

Common source labels in `network-topology-matrix.txt` and related outputs:

| Label | Meaning |
|---|---|
| `dns+synack` | direct DNS answer parsed from PCAP and observed connection confirmation |
| `dns+synack+norm` | direct `dns+synack` row normalized by a configured `dns_normalize` rule |
| `dns+conn+synack` | DNS name came from packet evidence, but the IP was backfilled from observed connectivity because the answer was incomplete or truncated |
| `sni+synack` | name came from TLS SNI and was confirmed by observed connection |
| `sni+conn+synack` | SNI-derived name with connectivity-backed IP inference |
| `active+synack` | name was obtained by active resolver lookup and later confirmed by observed connection |
| `active+conn+synack` | active-resolve name with connectivity-inferred IP |
| `active+matrix` | an otherwise-unattributed topology row was completed from an optional active-resolve result |
| `ptr+fcrdns+matrix` | a unique PTR name forward-resolved to the queried public IPv4 and completed an unattributed matrix row |
| `ptr+matrix` | a unique usable raw PTR name completed an unattributed matrix row without forward confirmation |
| `ptr-normalized+matrix` | a matching AWS EC2 IP-encoded PTR was normalized and completed an unattributed matrix row |
| `tls-cert-san+matrix` | an unresolved public TLS endpoint was decorated from the first usable leaf-certificate SAN, stripped wildcard base, or CN fallback |
| `tls-cert-san+matrix-fallback` | an unresolved public TCP endpoint was decorated from a usable certificate name found on fallback port `443` or `8443` after its exact port yielded none |
| `csv+conn` | DNS came from `dns-ip.csv` fallback on a non-mid-session row |
| `csv+mid` | DNS came from `dns-ip.csv` fallback for a mid-session row |
| `mid-session` | connection was observed without usable DNS attribution |
| `donated+ipport` | unresolved row was completed from direct `dns+synack` or `sni+synack` evidence on the same `(dstIP, proto, port)` |
| `donated+ipport+norm` | unresolved row was completed from normalized direct `dns+synack+norm` evidence on the same `(dstIP, proto, port)` |

Important details:

- CSV fallback, inferred DNS/SNI (`dns+conn+synack` / `sni+conn+synack`), active resolution, TLS certificate decoration (exact or fallback), and previously donated names never act as donors.
- Donation is run-local only; it is not persisted back into `dns-ip.csv`.
- Only direct `dns+synack`, normalized direct `dns+synack+norm`, and `sni+synack` rows can donate.
- One donor name is copied in full. Multiple names donate only their deterministic longest common DNS-label suffix when it contains at least two labels; otherwise the row remains unresolved.
- PTR completion runs after donation, cannot donate to other rows, and is not persisted back into `dns-ip.csv`.
- Strong direct evidence suppresses weaker conflicting CSV fallback where possible.
- DNS normalization rules apply after raw topology rows are built and before donation. They currently support only `type: dns_normalize`, only rewrite `dns+synack` rows, and preserve observed/normalized DNS metadata in JSON plus `dns-normalization-audit.csv`.

Minimal rule file example:

```yaml
rules:
  - rule_id: dns_normalize_tcsevplatform_evse
    type: dns_normalize
    net_id: 404163-1
    match:
      protocol: tcp
      ports: [9999, 443]
      observed_dns:
        - prod-ef.g2mobility.com
        - irve.61mobility.fr
        - evse-psa.total-ev-charge.com
        - total-ev-charge.com
        - "*.total-ev-charge.com"
      cname_contains:
        - iot.tcsevplatform.alzp.tgscloud.net
    set:
      normalized_dns: evse.total-ev-charge.com
```

`observed_dns` matching is case-insensitive and trims trailing dots. It supports
exact names and simple `*` glob patterns. If `cname_contains` is configured, a
row must have captured CNAME evidence that exactly matches, glob-matches, or
contains one of the configured CNAME values.

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
- unresolved or `mid-session` rows can inherit a name from another issuer in the same run on an exact `(dstIP, proto, port)` match, but only from direct `dns+synack` / `sni+synack` evidence; multiple direct names must share a suffix of at least two labels
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
| `--fleet` | string | empty | optional fleet IPv4 list; when set, scans fleet evidence and writes always-on server/probe summaries and flow-direction SQL |
| `--fleet-scan-workers` | int | `0` | workers for `--fleet` artifact scanning; `0` auto-selects `min(GOMAXPROCS, file_count)` with minimum `1`, `1` is sequential, higher values force concurrent scanning |
| `--format` | string | `table` | main output format: `table` or `json` |
| `--export-csv` | string | empty | optional CSV export path for main records |
| `--short`, `-s` | bool | `false` | squash topology to one row per issuer/DNS/port |
| `--radius-imsi` | bool | `false` | map issuer IPs to IMSI via RADIUS Accounting data |
| `--only-tcp` | bool | `false` | only correlate TCP connections |
| `--infer-dns-from-connections` | bool | `false` | opt in to issuer-only query/connection timing inference when DNS answers are missing |
| `--ignore-ntp` | bool | `true` | drop NTP-like DNS names using heuristic filtering |
| `--dns-ip-file` | string | empty | path to fallback DNS/IP map used for last-resort attribution |
| `--dns-normalization-rules` | string | empty | optional YAML file with `dns_normalize` rules applied to direct DNS topology rows before donation |
| `--exclude-ports` | string | `53` | comma-separated destination/server ports to exclude from topology correlation |
| `--ftp-control-ports` | string | `21,990` | strict comma-separated passive FTP/FTPS control ports; replaces the default set |
| `--ftp-passive-min-port` | port | `30000` | minimum destination port heuristically suppressed after a configured FTP/FTPS control channel is observed |
| `--server-summary-exclude-udp-ports` | port/range set | `33434-33534` | UDP destination ports excluded only from public/private server summary artifacts; empty disables |
| `--active-resolve` | bool | `false` | resolve unresolved names against external resolvers |
| `--active-resolvers` | string | empty | comma-separated resolver IPs for active resolve |
| `--reverse-dns-lookup` | bool | `false` | use bounded PTR/forward-confirmation lookup as last-resort topology completion and write its audit CSV |
| `--tls-cert-lookup` | bool | `false` | probe unresolved public TLS endpoints, decorate exact matching matrix rows, and write a certificate audit CSV |
| `--tls-cert-lookup-timeout` | integer seconds | `15` | per-endpoint TCP connection plus TLS certificate handshake timeout; valid range `5..30` |
| `--disable-sni` | bool | `false` | skip TLS ClientHello/SNI scan |
| `--unsorted` | bool | `false` | preserve natural first-seen issuer order in topology output |
| `--debug` | bool | `false` | emit additional debug artifacts, including detailed fleet trail/unique CSVs and CSV append audit |
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
