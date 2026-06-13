# Repo Summary

## Purpose

`pcaptool` is an offline CLI for turning a directory of packet captures into stable machine-readable artifacts about DNS attribution, connectivity, and service endpoints. The core problem it solves is that real capture sets are often incomplete: DNS queries may be visible while DNS responses are truncated, missing, or unparsable, so the tool combines direct parsing with conservative correlation and fallback heuristics.

The main downstream contract is not just the human-readable tables. It is the per-run output directory plus `_run-artifacts.json`, which records the run identity and the artifact file paths.

## True CLI Entrypoint

- Binary entrypoint: [`main.go`](/home/alex/go/src/github.com/aglants/pcaptool/main.go)
- Effective processing entrypoint: [`cmd/dnsextract.go`](/home/alex/go/src/github.com/aglants/pcaptool/cmd/dnsextract.go)

`main.go` only prints the banner and delegates to Cobra. The real operational path is `pcaptool dnsextract`. No other substantive command path showed up in this onboarding pass.

## Top-Level Architecture

- `main` and `cmd`: CLI wiring, flag parsing, run directory creation, manifest writing, and optional post-hooks.
- `internal/pcap`: recursive discovery of capture files under `--read-dir`.
- `internal/dns`: dominant domain package. It owns DNS/SNI extraction, DNS-to-connection correlation, attribution heuristics, flattened output records, topology construction, unresolved tracking, and fallback-map updates.
- `internal/connectivity`: packet-to-edge extraction for observed issuer-to-destination connectivity.
- `internal/radius`: optional enrichment path that maps issuer IPs to IMSI labels from RADIUS Accounting traffic.
- `output`: rendering of the final table, JSON, CSV, topology, and reporting files.
- `progress`: terminal progress/status reporting.

## Main Runtime Path

1. `main.main` prints the banner and calls `cmd.Execute()`.
2. Cobra resolves `dnsextract` and enters `runDNSExtract`.
3. `cmd.NewOutputManager` creates the run directory at `<output-root>/<net-id>/<run-id>/`.
4. `pcap.DiscoverPCAPFiles` walks `--read-dir`, filters `.pcap` / `.pcapng` / `.cap`, and sorts the file list.
5. Optional: `radius.BuildIMSIIndexFromPCAPs` builds a time-aware IP-to-IMSI index from RADIUS Accounting traffic.
6. `dns.BuildTransactionsWithSNIFromPCAPs` scans the corpus for DNS query/response transactions and, unless disabled, TLS ClientHello SNI observations.
7. Optional: `dns.FilterOutNTPDNSTransactions` drops NTP/time-sync names.
8. Optional: `dns.ResolveUnresolvedDNSTransactions` actively resolves unresolved names and marks the evidence as active lookup.
9. Optional: `dns.LoadIPToDNSFromFile` loads the fallback `dns-ip.csv` map.
10. `dns.AttachConnectionsAndCollectEdgesFromPCAPs` rescans the corpus to:
    - collect observed connectivity edges
    - attach connections back to DNS transactions
    - backfill or confirm IP evidence conservatively
11. `dns.ToOutputRecords`, `dns.FilterAndDedupRecords`, and `dns.SortOutputRecords` prepare the main DNS table rows.
12. `dns.BuildNetworkTopologyMatrixEntriesWithOptions` joins connectivity edges with DNS, SNI, active-resolve, and CSV evidence and applies final attribution heuristics.
13. Secondary outputs are derived from the same run state:
    - `dns.BuildServiceEndpoints`
    - `dns.ComputeUnresolvedDNSFirstSeen`
    - `dns.BuildExternalEndpoints`
    - `dns.PublicUnresolvedDestinationEndpoints`
14. `output.*` writes the files, `writeRunArtifactsManifest` writes `_run-artifacts.json`, and optional post-hooks run with `PCAPTOOL_MANIFEST` set.

## Where Parsing Ends And Heuristics Begin

Direct parsing/extraction mostly ends after these steps:

- [`internal/dns/extractors.go`](/home/alex/go/src/github.com/aglants/pcaptool/internal/dns/extractors.go) and [`internal/dns/from_pcap_names.go`](/home/alex/go/src/github.com/aglants/pcaptool/internal/dns/from_pcap_names.go) recover DNS queries/responses, including truncated DNS salvage.
- [`internal/dns/tls_sni.go`](/home/alex/go/src/github.com/aglants/pcaptool/internal/dns/tls_sni.go) extracts SNI from TLS ClientHello payloads.
- [`internal/connectivity/collector.go`](/home/alex/go/src/github.com/aglants/pcaptool/internal/connectivity/collector.go) turns packet flows into observed `(issuer, dst, proto, port, firstSeen)` edges.
- [`internal/radius`](/home/alex/go/src/github.com/aglants/pcaptool/internal/radius) parses RADIUS Accounting messages into session windows.

Inference/heuristics begin when parsed artifacts are correlated or enriched:

- [`internal/dns/from_pcap.go`](/home/alex/go/src/github.com/aglants/pcaptool/internal/dns/from_pcap.go): issuer-only fallback matching, observed-connection marking, CSV guards, and FTP passive suppression.
- [`internal/dns/unresolved_resolver.go`](/home/alex/go/src/github.com/aglants/pcaptool/internal/dns/unresolved_resolver.go): optional active resolution of unresolved names.
- [`internal/dns/network_topology_matrix.go`](/home/alex/go/src/github.com/aglants/pcaptool/internal/dns/network_topology_matrix.go): time-window matching, CSV fallback, mid-session handling, strong-DNS-over-CSV precedence, peer completion, and unresolved-row suppression.
- [`internal/dns/dns_ip_file.go`](/home/alex/go/src/github.com/aglants/pcaptool/internal/dns/dns_ip_file.go): merge and append rules for the persistent fallback map.

## Highest-Risk Areas

- `internal/dns/from_pcap.go`: correlation and fallback logic can change which IPs get attached to which names, which affects nearly every downstream artifact.
- `internal/dns/network_topology_matrix.go`: this is the main output-semantics package; many ranking, deduplication, and fallback rules terminate here.
- `internal/dns/extractors.go` and `internal/dns/tls_sni.go`: truncated-capture behavior is fragile; small changes can silently lose or invent evidence.
- `internal/dns/dns_ip_file.go`: learned fallback-map persistence affects replay and future runs, not just the current invocation.
- `internal/radius/*`: time-window mistakes change issuer identity labeling rather than just presentation.

## Safe Modification Mindset

- Treat `DNSTransaction`, `TopologyEntry`, `OutputRecord`, and `_run-artifacts.json` as contract-bearing structures.
- Prefer conservative misses over optimistic attribution when captures are truncated or ambiguous.
- Separate packet parsing changes from attribution-policy changes when possible; both are high sensitivity, but the regression shape is different.
- Anchor changes with targeted regression tests around truncated DNS salvage, fallback-map ambiguity, topology attribution precedence, and replay-safe append behavior.

## Uncertainties From This Pass

- `README.md` lists `completion` as part of the command surface, but the `cmd/` tree only explicitly registers `dnsextract` during this pass. That mismatch should be verified in the next onboarding step.
- `internal/pcap/event.go`, `dns.BuildTransactionsFromEvents`, and `dns.AttachConnections` look like an older event-based path and do not appear on the current `dnsextract` hot path.
- `internal/dns/from_tls.go` duplicates SNI-to-transaction logic, but the current runtime path uses `BuildTransactionsWithSNIFromPCAPs`. The intended ownership between those paths should be clarified in the next onboarding pass.

## Primary contract-bearing types
- DNSTransaction
- TopologyEntry
- OutputRecord
- _run-artifacts.json