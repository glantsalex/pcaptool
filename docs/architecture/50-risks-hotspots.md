# Risks And Hotspots

Scope: prioritized hotspots on the active `pcaptool dnsextract` path only. Each item names why the area is dangerous, what can break, what to re-check, and how to approach modifications safely.

## Top 10 Hotspots

| priority | location | risk class | why it is dangerous | bug types it could introduce | artifacts / tests / contracts affected | safe modification notes |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | `internal/dns/network_topology_matrix.go` `BuildNetworkTopologyMatrixEntriesWithOptions` | semantic, output-contract, control-flow | This is where multiple evidence sources, CSV fallback, peer completion, and suppression rules terminate into final topology semantics. | Wrong DNS attribution, dropped rows, duplicate rows, cross-port contamination, resolver leakage, broken source labels. | `network-topology-matrix.txt/json`, `service-endpoints.txt`, `external-endpoints.txt`, `dns-unresolved-dns.txt`, `unresolved-ip.json`; check `internal/dns/network_topology_matrix_test.go`, `output/connectivity_matrix_test.go`, `internal/dns/unresolved_stats_test.go`, `internal/dns/service_endpoints_test.go`. | Change one precedence rule at a time. Re-check private/public behavior, CSV ambiguity handling, and unresolved-row suppression together. |
| 2 | `internal/dns/from_pcap.go` `AttachConnectionsAndCollectEdgesFromPCAPs` | semantic, control-flow | It decides whether a connection can safely mutate a DNS transaction and whether an observed edge exists at all. | False positive connection matches, name poisoning from issuer fallback, missed connections, protocol/port mis-selection. | `DNSTransaction`, main table rows, topology rows, learned CSV append eligibility; check `internal/dns/from_pcap_test.go`, downstream topology tests. | Preserve the direct-match-first and ambiguity-means-drop invariants. Avoid broadening fallback windows casually. |
| 3 | `internal/dns/extractors.go` raw DNS salvage helpers | semantic | Truncated-capture recovery is the repo’s main parsing differentiator. Slight parser changes can silently invent or lose evidence. | Partial-name corruption, accepting malformed payloads, rejecting salvageable packets, wrong A-record extraction. | `DNSTransaction`, main table, topology, unresolved reports; check `internal/dns/extractors_truncated_test.go`. | Keep salvage logic bounds-checked and A-query/response scoped. Prefer missing evidence over speculative decoding. |
| 4 | `internal/connectivity/collector.go` | semantic, control-flow, performance | Connectivity edges are the substrate for later attribution; direction, exclusion, and FTP suppression are all policy-bearing. | Swapped issuer/destination, missing or extra UDP/TCP edges, FTP passive false positives, port-exclusion drift. | `[]Edge`, topology rows, unresolved endpoints; check `internal/connectivity/collector_test.go`, `internal/dns/from_pcap_test.go`. | Re-check TCP confirmed edges, UDP symmetry, excluded ports, and FTP passive suppression together. |
| 5 | `internal/dns/dns_ip_file.go` | replay-related, semantic | This file controls both reuse of historical fallback data and persistence of new learned pairs. Mistakes survive the current run. | Polluted fallback CSV, unstable replay behavior, accidental persistence of inferred or private evidence, nondeterministic merge results. | `dns-ip.csv`, future topology attribution, `ip-dns-append-audit.txt`; check `internal/dns/dns_ip_file_update_test.go`, `internal/dns/ip_dns_audit_test.go`, `output/ip_dns_audit_test.go`. | Treat persistence rules as stricter than current-run attribution rules. Do not relax “only strong direct public evidence is learnable” without new regression coverage. |
| 6 | `internal/radius/radius_session_builder.go` and `internal/radius/index.go` | semantic, replay-related, control-flow | Time-window construction changes issuer identity, grouping, and chronology across the whole run. | Wrong IMSI assignment, session overlap bugs, stale/late window reuse, issuer relabeling drift. | `DNSTransaction.IssuerLabel`, table grouping, topology issuer keys, issuer profiles. Visible tests were limited in this pass. | Make time-window assumptions explicit before touching this code. Verify Start/Interim/Stop, synthetic opens, and coalescing behavior end-to-end. |
| 7 | `internal/dns/unresolved_resolver.go` | semantic, control-flow | Optional active resolve can turn unresolved names into concrete IP evidence mid-run. | Resolver-induced name pollution, over-resolution of junk names, hidden unresolveds, inconsistent source labels. | `DNSTransaction`, main table, topology rows, unresolved outputs. Dedicated tests were not obvious in this pass. | Preserve the strict name filter and the degrade-to-unresolved behavior on lookup failure. Treat this path as under-tested. |
| 8 | `internal/dns/ntp_filter.go` and `internal/dns/name_heuristics.go` | semantic | These small filters decide what names are even eligible for later inference. | Legitimate names dropped, noisy local/device names admitted, active-resolve scope widened unintentionally. | `DNSTransaction` set before correlation, unresolved outputs, active-resolve candidate pool; check `internal/dns/ntp_filter_test.go`. | Keep these filters conservative and explicit. Add examples before expanding pattern coverage. |
| 9 | `cmd/dnsextract.go` orchestration around side effects | control-flow, replay-related, output-contract | The order of optional passes and writes determines whether failures leave partial side effects, especially CSV append vs later write/post-hook failure. | Partial run artifacts, manifest mismatch, replay-affecting append before final failure, missing derived outputs. | run directory layout, `_run-artifacts.json`, post-hook behavior, fallback CSV; check `cmd/post_hook_test.go`, `cmd/output_manager_test.go`. | Preserve the current pass ordering unless the side-effect model is intentionally reconsidered. Be explicit about what may already be written on failure. |
| 10 | `internal/dns/service_endpoints.go` and `internal/dns/stats.go` | output-contract, semantic | These files translate topology into downstream-facing summaries and placeholders. Small changes here can skew inventories even if topology stays stable. | Wrong deduping, unstable hashes, incorrect synthetic placeholders, unresolved-report drift by name vs issuer. | `service-endpoints.txt`, `dns-unresolved-dns.txt`; check `internal/dns/service_endpoints_test.go`, `internal/dns/unresolved_stats_test.go`, `output/service_endpoints_test.go`, `output/unresolved_table_test.go`. | Treat these as contract shapers. Re-check placeholder rules and global-by-name unresolved semantics before modifying. |

## Best Safe Entry Points For Future Changes

- `output/*.go` formatting-only changes that do not alter row selection or field meaning.
- `cmd/output_manager.go` when adjusting path handling without changing the run directory contract.
- `progress/progress.go` for operator-facing status changes.
- Documentation and architecture files under `docs/architecture/`.

## Areas To Avoid Casual Modification

- `internal/dns/network_topology_matrix.go`
- `internal/dns/from_pcap.go`
- `internal/dns/extractors.go`
- `internal/dns/dns_ip_file.go`
- `internal/radius/radius_session_builder.go`
- `internal/connectivity/collector.go`

These are the places where a seemingly local tweak can change output semantics, replay behavior, or the set of attributed endpoints across the whole run.

## Safe Modification Notes By Zone

- Parsing zone:
  - safest changes are instrumentation and narrow bug fixes with packet fixtures
  - avoid widening accepted payload shapes without new truncation regression coverage
- Correlation zone:
  - safest changes keep current ambiguity thresholds and only improve observability or tighten obviously unsafe matches
  - avoid relaxing issuer-only fallback casually
- Fallback attribution zone:
  - safest changes are explicit precedence fixes paired with new topology tests
  - avoid changing CSV ambiguity rules, peer completion, or suppression ordering piecemeal
- Persistence / replay zone:
  - safest changes are audit and validation improvements
  - avoid broadening what counts as “learnable” without replay-focused regression cases
- Identity zone:
  - safest changes are performance or diagnostics work that preserves session-window semantics
  - avoid touching Start / Interim / Stop logic casually

## Remaining Ambiguities

- `internal/dns/from_tls.go` overlaps with the active `sniExtractor` path and initializes SNI evidence differently.
- `internal/dns/name_ip_evidence_index.go` looks unused on the active path.
- The older event-based path remains present and should be explicitly classified as dormant or supported in a later pass.
- RADIUS logic is clearly active but appears less test-anchored than the DNS/topology heuristics.
