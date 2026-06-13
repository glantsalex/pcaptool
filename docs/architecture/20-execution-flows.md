# Execution Flows

Scope: this document refines the current `pcaptool dnsextract` runtime into three concrete flows. It is grounded in the active code path, not the older event-based helpers under `internal/pcap` and `internal/dns/correlate.go`.

## 1. Happy Path

### Ordered stages

| stage | owning package / function | major types | notes |
| --- | --- | --- | --- |
| 1. CLI dispatch and fail-fast validation | `main.main` -> `cmd.Execute` -> `cmd.runDNSExtract` | raw args, `cmd.OutputManager` | Validates `--format` and `--topology-dns-window`, then creates the run directory. |
| 2. Input discovery | `cmd.NewOutputManager`, `pcap.DiscoverPCAPFiles` | `cmd.OutputManager`, `[]string` PCAP paths | Canonical per-run layout is fixed before packet processing starts. |
| 3. Corpus extraction | `dns.BuildTransactionsWithSNIFromPCAPs` | `[]*dns.DNSTransaction`, internal `dns.TxKey` buckets | One scan extracts DNS transactions plus synthetic SNI-backed transactions when SNI is enabled. |
| 4. Optional light filtering | `dns.FilterOutNTPDNSTransactions` | `[]*dns.DNSTransaction` | Default path drops obvious NTP/time-sync names before correlation. |
| 5. Connection correlation | `dns.AttachConnectionsAndCollectEdgesFromPCAPs` | `[]*dns.DNSTransaction`, `[]connectivity.Edge`, `dns.FirstPacketInfo` | Second corpus scan attaches best connection candidates and emits observed connectivity edges. |
| 6. Issuer labeling and record prep | `runDNSExtract`, `dns.ToOutputRecords`, `dns.FilterAndDedupRecords`, `dns.SortOutputRecords` | mutated `DNSTransaction`, `[]dns.OutputRecord` | Default issuer label is the issuer IP. Records with no matched destination port are dropped from the main table output. |
| 7. Topology derivation | `dns.BuildNetworkTopologyMatrixEntriesWithOptions` | `[]connectivity.Edge`, `[]dns.TopologyEntry` | Joins connectivity edges back to name evidence and builds the final connectivity matrix rows. |
| 8. Secondary derivations | `dns.BuildServiceEndpoints`, `dns.ComputeUnresolvedDNSFirstSeen`, `dns.BuildExternalEndpoints`, `dns.PublicUnresolvedDestinationEndpoints` | `[]dns.ServiceEndpoint`, `[]dns.DNSUnresolvedStat`, `[]*dns.ExternalEndpoint`, `[]dns.UnresolvedIPEndpoint` | All are derived from `DNSTransaction` and `TopologyEntry`, not from fresh packet scans. |
| 9. Materialization | `output.*`, `writeRunArtifactsManifest` | on-disk files, `cmd.RunArtifactsManifest` | Writes the human/machine outputs and the final manifest contract. |

### Control-flow pivots

- `cmd.runDNSExtract` is the main orchestration pivot. This is where optional passes are enabled or skipped.
- `dns.BuildTransactionsWithSNIFromPCAPs(..., !flagDisableSNI)` is the first meaning-changing branch: SNI transactions either enter the run or never exist.
- `dns.AttachConnectionsAndCollectEdgesFromPCAPs` is the pivot where parsed DNS names become connection-backed candidates and edge observations.
- `dns.BuildNetworkTopologyMatrixEntriesWithOptions` is the final semantics pivot. After this stage, the run has committed to its issuer-to-destination attribution story.

### Risk notes

- `DNSTransaction` is mutated across multiple stages, so ordering matters.
- The main DNS table and the topology matrix are derived from the same transaction set but apply different filtering and attribution rules.
- Output semantics depend on deterministic ordering at several stages: sorted PCAP discovery, sorted transaction buckets, and topology sort behavior.

## 2. Heuristic / Attribution Path

### Ordered stages

| stage | owning package / function | major types | notes |
| --- | --- | --- | --- |
| 1. Incomplete evidence enters the run | `dns.BuildTransactionsWithSNIFromPCAPs` | `[]*dns.DNSTransaction`, `dns.Evidence` | Transactions may have only a query name, only SNI, partial answers, or no resolved IPs. |
| 2. Active resolution branch | `dns.DefaultResolveUnresolvedOptions`, `dns.ResolveUnresolvedDNSTransactions` | mutated `DNSTransaction`, `dns.Evidence` | Optional pass that injects IPv4 answers with `EvActiveResolve` when unresolved names still look resolvable. |
| 3. Fallback-map load branch | `dns.LoadIPToDNSFromFile` | `map[string][]string` IP->DNS map | Makes CSV fallback available to both correlation guards and topology attribution. |
| 4. Safe connection backfill | `dns.AttachConnectionsAndCollectEdgesFromPCAPs` | mutated `DNSTransaction`, `dns.ConnCandidate`, `dns.FirstPacketInfo`, `[]connectivity.Edge` | Direct `(issuer,dst)` matches win. If no match exists, TCP-only issuer fallback may infer a match, but UDP fallback is explicitly disabled. |
| 5. CSV guard on inferred matches | `allowConnectionInferredDNSBackfill` | candidate `DNSTransaction`, CSV map | Even when TCP fallback finds a candidate transaction, CSV can veto the inferred binding if the IP conflicts with a known single-name mapping. |
| 6. Identity enrichment branch | `radius.BuildIMSIIndexFromPCAPs`, `IMSIIndex.Lookup`, `runDNSExtract` issuer loop | `radius.SessionWindow`, `radius.IMSIIndex`, mutated `DNSTransaction` | Optional path that replaces issuer IP labels with IMSI labels in both table and topology views. |
| 7. Learned fallback-map update | `dns.StrongObservedIPDNSPairsFromTransactions`, `dns.MergeIPToDNSMaps`, `dns.AppendIPDNSPairsToFile` | `[]dns.IPDNSPair`, optional `[]dns.IPDNSAppendAuditRecord` | Strong `dns+synack` observations can be persisted back into the CSV fallback map for future runs. |
| 8. Final topology attribution | `dns.BuildNetworkTopologyMatrixEntriesWithOptions` | `[]dns.TopologyEntry`, `dns.TopologyBuildOptions` | Best-match lookup, CSV `mid-session` / `csv+conn`, strong-DNS-over-CSV suppression, peer completion, unresolved retention, and optional short squashing all happen here. |

### Control-flow pivots

- `flagActiveResolve` changes whether unresolved names remain unresolved working state or become active-resolve evidence.
- `flagDNSIPFile` changes both current-run attribution behavior and future-run replay state through CSV append.
- `AttachConnectionsAndCollectEdgesFromPCAPs` has the sharpest internal branch:
  - direct `(issuer,dst)` transaction match
  - TCP issuer-only fallback via `pickFallbackTxUniq`
  - skip due to ambiguity, UDP, time-window miss, or CSV veto
- `BuildNetworkTopologyMatrixEntriesWithOptions` branches on:
  - `bestTx != nil` vs no match
  - private destination vs public destination
  - `csv+mid` / `csv+conn` / unresolved
  - strong DNS suppression of weaker CSV fallback
  - peer completion donor available vs ambiguous vs absent
- `flagRadiusIMSI`, `flagConnectivityShort`, `flagUnsorted`, and `flagTopologyDNSWindow` materially change the final shape or ordering of the topology.

### Risk notes

- This path is where parsed evidence turns into inferred attribution. Small changes here can silently alter downstream semantics.
- CSV append is replay-sensitive: the current run can change the behavior of later runs.
- The topology builder is intentionally conservative in some places and opportunistic in others; those precedence rules are test-anchored and easy to destabilize.

## 3. Failure / Fallback Path

### Ordered stages

| stage | owning package / function | major types | notes |
| --- | --- | --- | --- |
| 1. Early hard failures | `cmd.runDNSExtract`, `cmd.NewOutputManager`, `pcap.DiscoverPCAPFiles`, `parseResolverServers`, `parsePortSet` | flags, `cmd.OutputManager` | Invalid format, negative DNS window, bad `--net-id`, no PCAPs, invalid ports, or invalid resolver IPs stop the run immediately. |
| 2. Packet-level salvage or skip | `dnsExtractor.OnPacket`, `extractDNSQueryNameFromRaw`, `extractDNSResponseFromRaw`, `extractSNIFromClientHello` | partial packet payloads, `DNSTransaction` | Truncated DNS may still yield partial names or answers; truncated/non-ClientHello TLS payloads are simply ignored. |
| 3. Soft degradation in enrichment | `dns.ResolveUnresolvedDNSTransactions`, `radius.BuildIMSIIndexFromPCAPs` | mutated `DNSTransaction`, `radius.IMSIIndex` | Per-name resolution failures do not abort the run; names stay unresolved. No usable RADIUS messages yields an empty IMSI index rather than a hard failure. |
| 4. Safe suppression in correlation | `dns.AttachConnectionsAndCollectEdgesFromPCAPs` | `DNSTransaction`, `ConnCandidate`, `Edge` | Ambiguous issuer-only matches are skipped. UDP issuer-only fallback is disabled. Out-of-window or CSV-conflicting inferred matches are discarded. |
| 5. Safe fallback in final attribution | `dns.BuildNetworkTopologyMatrixEntriesWithOptions`, `dns.BuildServiceEndpoints`, `dns.PublicUnresolvedDestinationEndpoints` | `TopologyEntry`, `ServiceEndpoint`, `UnresolvedIPEndpoint` | If no safe attribution exists, rows remain unresolved, private destinations stay unnamed, and service endpoints use synthetic markers like `[no-dns-attribution]`. |
| 6. Late hard failures after side effects | `dns.AppendIPDNSPairsToFile`, `output.*`, `writeRunArtifactsManifest`, `copyFile`, `runPostHooks` | files, `RunArtifactsManifest` | File creation/write errors and post-hook failures abort the run even after earlier outputs or CSV updates may already have happened. |

### Control-flow pivots

- Hard fail vs soft degrade is not uniform:
  - bad configuration and write failures abort
  - unresolved DNS lookup failures usually degrade to unresolved output
  - ambiguous attribution decisions are intentionally skipped
- `extractDNS*FromRaw` is the packet-level salvage pivot for truncated captures.
- `AttachConnectionsAndCollectEdgesFromPCAPs` is the safe-suppression pivot: it prefers dropping a candidate over poisoning attribution.
- `BuildNetworkTopologyMatrixEntriesWithOptions` is the fallback-output pivot: unresolved rows are preserved rather than hidden.

### Risk notes

- This flow mixes fail-fast behavior with best-effort degradation, so partial side effects are possible.
- The most important replay risk is that learned `dns-ip.csv` pairs can be appended before a later output or post-hook step fails.
- “Failure” often means “emit explicit unresolved artifacts” rather than “stop the process,” so downstream operators need the manifest and unresolved reports together to understand run quality.

## Open Ambiguities For The Next Pass

- `internal/pcap.Event`, `dns.BuildTransactionsFromEvents`, and `dns.AttachConnections` still look like an older event-based flow rather than part of `dnsextract`.
- `internal/dns/from_tls.go` builds synthetic SNI-backed `DNSTransaction` values too, but the active path uses `sniExtractor` inside `BuildTransactionsWithSNIFromPCAPs`.
- Those two SNI paths do not initialize `DNSTransaction` identically: `from_tls.go` sets `NameEvidence: EvSNI`, while `sniExtractor` currently builds the transaction without that field populated.
- `internal/dns/name_ip_evidence_index.go` defines evidence-index helpers that appear unused on the current hot path.
- Two separate `L4Proto` types exist in `internal/dns` and `internal/connectivity` with the same logical values but different ownership.
