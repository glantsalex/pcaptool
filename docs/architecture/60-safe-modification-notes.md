# Safe Modification Notes

Use this file as the practical companion to the earlier architecture docs. It is scoped to the active `pcaptool dnsextract` path, not to every historical helper in the repo.

## Parser behavior changes

- `Where to start`: read [`20-execution-flows.md`](./20-execution-flows.md), then [`40-heuristics-catalog.md`](./40-heuristics-catalog.md) sections 1-4, then inspect `internal/dns/extractors.go`, `internal/dns/tls_sni.go`, and `internal/connectivity/collector.go`.
- `Fragile invariants`:
  - truncated payload salvage must stay bounds-checked and conservative
  - missing evidence is safer than invented evidence
  - DNS salvage is intentionally narrow; A-query / A-response behavior matters most
  - connectivity extraction must preserve tuple direction, protocol, and port semantics
- `Likely downstream effects`: `DNSTransaction` creation, `OutputRecord` population, topology attribution quality, unresolved reporting, learned `dns-ip.csv` append eligibility.
- `Tests to inspect first`:
  - `internal/dns/extractors_truncated_test.go`
  - `internal/connectivity/collector_test.go`
  - `internal/dns/from_pcap_test.go`
- `Safe modification advice`:
  - add or change one parser rule at a time
  - keep malformed or partial payload behavior explicit
  - do not combine parsing broadening with downstream attribution changes in one patch

## DNS-to-connection correlation changes

- `Where to start`: read [`20-execution-flows.md`](./20-execution-flows.md) happy-path and heuristic-path sections, [`30-data-models.md`](./30-data-models.md) entries for `DNSTransaction`, `ConnCandidate`, and `Edge`, then inspect `internal/dns/from_pcap.go`.
- `Fragile invariants`:
  - direct `(issuer,dstIP)` evidence wins before fallback logic
  - issuer-only fallback is TCP-only
  - ambiguous fallback candidates are dropped, not guessed through
  - time-window checks such as `maxConnDelay` are semantic, not tuning noise
  - CSV-backed inferred matches must not silently overwrite stronger run-local evidence
- `Likely downstream effects`: destination port / protocol assignment, observed-connection evidence, main DNS table shape, topology rows, service endpoints, learned-pair eligibility.
- `Tests to inspect first`:
  - `internal/dns/from_pcap_test.go`
  - `internal/dns/network_topology_matrix_test.go`
  - `internal/dns/unresolved_stats_test.go`
- `Safe modification advice`:
  - preserve the "ambiguity means drop" rule unless the design is explicitly changing repo semantics
  - if correlation drift appears, inspect `DNSTransaction` mutation before touching topology code
  - avoid widening fallback windows casually; replay behavior changes can hide behind small diffs here

## Topology attribution changes

- `Where to start`: read [`20-execution-flows.md`](./20-execution-flows.md) heuristic and failure/fallback flows, [`30-data-models.md`](./30-data-models.md) for `TopologyEntry`, then inspect `internal/dns/network_topology_matrix.go`, `internal/dns/service_endpoints.go`, and `internal/dns/unresolved_ip.go`.
- `Fragile invariants`:
  - private destinations must not gain invented DNS names
  - strong DNS evidence must outrank CSV fallback
  - unresolved rows are preserved when no safe attribution exists
  - peer completion must remain unique-donor-only
  - suppression rules must stay consistent across topology, unresolved-DNS, and service-endpoint outputs
- `Likely downstream effects`: `network-topology-matrix.txt/json`, `service-endpoints.txt`, `external-endpoints.txt`, `dns-unresolved-dns.txt`, `unresolved-ip.json`.
- `Tests to inspect first`:
  - `internal/dns/network_topology_matrix_test.go`
  - `internal/dns/service_endpoints_test.go`
  - `internal/dns/unresolved_stats_test.go`
  - `output/connectivity_matrix_test.go`
  - `output/service_endpoints_test.go`
  - `output/unresolved_table_test.go`
- `Safe modification advice`:
  - change one precedence rule at a time
  - verify unresolved suppression and peer completion together, not separately
  - treat `TopologyEntry` changes as output-contract work even when the edit looks "internal"

## Fallback CSV / replay changes

- `Where to start`: read [`20-execution-flows.md`](./20-execution-flows.md) failure/fallback flow, [`30-data-models.md`](./30-data-models.md) for `IPDNSPair`, then inspect `internal/dns/dns_ip_file.go` and `internal/dns/ip_dns_audit.go`.
- `Fragile invariants`:
  - persistence rules are stricter than current-run attribution rules
  - only strong direct public evidence is learnable
  - inferred, private, or low-confidence mappings must not be written back to `dns-ip.csv`
  - repeated processing should remain deterministic for identical inputs
- `Likely downstream effects`: `dns-ip.csv`, `ip-dns-append-audit.txt`, future run attribution, replay safety, backfill consistency.
- `Tests to inspect first`:
  - `internal/dns/dns_ip_file_update_test.go`
  - `internal/dns/ip_dns_audit_test.go`
  - `output/ip_dns_audit_test.go`
- `Safe modification advice`:
  - separate "can use now" from "can persist for future runs"
  - review append-order and duplicate-handling behavior before touching merge logic
  - treat this area as replay-sensitive even if the current change only targets one run

## RADIUS identity changes

- `Where to start`: read [`20-execution-flows.md`](./20-execution-flows.md) happy-path notes on optional IMSI enrichment, [`30-data-models.md`](./30-data-models.md) entries for `SessionWindow` and `IMSIIndex`, then inspect `internal/radius/radius_session_builder.go` and `internal/radius/index.go`.
- `Fragile invariants`:
  - session windows are time-aware and order-sensitive
  - Start / Interim / Stop handling must stay coherent
  - synthetic open sessions change identity labeling semantics
  - lookup failure must degrade to raw issuer IP labeling, not to invented identity
- `Likely downstream effects`: issuer grouping in the main table, topology issuer keys, issuer profile output, cross-PCAP consistency when `--radius-imsi` is enabled.
- `Tests to inspect first`:
  - no dedicated RADIUS-focused tests were obvious in this onboarding pass
  - inspect downstream integration anchors first: `internal/dns/from_pcap_test.go`, topology tests, and any fixture-driven runs that exercise `--radius-imsi`
- `Safe modification advice`:
  - make time-window assumptions explicit before editing
  - verify behavior across overlapping or missing session events
  - treat this zone as architecture-review-first if the change affects identity semantics rather than only parsing hygiene

## Output / report formatting changes

- `Where to start`: read [`30-data-models.md`](./30-data-models.md) contract-bearing types, then inspect `output/*.go` and `cmd/post_hook.go`.
- `Fragile invariants`:
  - field meaning matters more than row formatting
  - manifest shape and file naming are downstream contracts
  - formatting-only edits must not alter row selection, ordering semantics, or omission rules unless that is the intended change
- `Likely downstream effects`: table/CSV/JSON consumers, post-hooks, automation that reads `RunArtifactsManifest`.
- `Tests to inspect first`:
  - `output/connectivity_matrix_test.go`
  - `output/service_endpoints_test.go`
  - `output/unresolved_table_test.go`
  - `output/ip_dns_audit_test.go`
  - `cmd/post_hook_test.go`
- `Safe modification advice`:
  - keep formatting changes separate from semantic row-generation changes
  - if output drift appears only in emitted files, inspect writer code after verifying the upstream `OutputRecord` or `TopologyEntry` slices
  - preserve stable file names and manifest references unless a contract change is intentional and documented

## Safest entry points for low-risk contributions

- docs under `docs/architecture/`
- `progress/progress.go`
- output writer formatting in `output/*.go` when the row set and field meaning stay unchanged
- small CLI help or flag-description clarifications in `cmd/dnsextract.go` that do not alter control flow

## Medium-risk changes that need targeted tests

- parser filters in `internal/dns/extractors.go`, `internal/dns/ntp_filter.go`, and `internal/dns/name_heuristics.go`
- connectivity extraction in `internal/connectivity/collector.go`
- output shaping that depends on topology semantics but does not rewrite precedence rules
- `cmd/dnsextract.go` changes that affect optional features, artifact ordering, or side-effect timing

## High-risk zones that require explicit architecture review first

- `internal/dns/network_topology_matrix.go`
- `internal/dns/from_pcap.go`
- `internal/dns/dns_ip_file.go`
- `internal/radius/radius_session_builder.go`
- active-resolve behavior in `internal/dns/unresolved_resolver.go`

## What to change first when debugging output drift

1. Identify which artifact drifted first: main DNS table, topology matrix, unresolved outputs, service endpoints, audit files, or manifest.
2. Check whether the drift already exists in `DNSTransaction` / `OutputRecord` state before touching topology or writers.
3. If the main table is stable but topology drifted, inspect precedence, CSV fallback, unresolved suppression, and peer completion in `internal/dns/network_topology_matrix.go`.
4. If only replay-related artifacts drifted, inspect `dns-ip.csv` read/append logic before changing correlation heuristics.
5. If grouping or issuer labels drifted only when `--radius-imsi` is enabled, inspect the RADIUS session-window path before touching DNS logic.
6. Re-run the nearest targeted tests first. Do not start by changing multiple heuristic families at once.

## Open ambiguities to remember

- `internal/dns/from_tls.go` overlaps with the active `sniExtractor` path and initializes SNI-backed `DNSTransaction` values differently.
- `internal/dns/name_ip_evidence_index.go` looked inactive in the main path during onboarding.
- The older event-based flow still exists and should stay out of scope unless a future task proves it is live.
