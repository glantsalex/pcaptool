# Data Models

Scope: this inventory covers the most important data carriers on the active `pcaptool dnsextract` path. It intentionally skips small file-local helpers unless they materially affect control flow or final semantics.

## Classification Legend

- `contract-bearing`: directly shapes on-disk artifacts or persisted behavior
- `heuristic-state`: mutable working state whose evolution determines attribution semantics
- `intermediate`: transient join/index/report-building state

## Contract-Bearing Types

| name | package / file | purpose | produced by | consumed by | mutated? yes/no and where | contract importance | risk / notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `RunArtifactsManifest` | `cmd/post_hook.go` | Machine-readable per-run manifest of file paths and run metadata. | `writeRunArtifactsManifest` | downstream tooling, post-hooks, manifest copy path | No; built once then JSON-encoded | contract-bearing | This is the repo’s clearest downstream contract. |
| `OutputRecord` | `internal/dns/output.go` | Flattened DNS table row for `dns-table.txt/json/csv`. | `dns.ToOutputRecords` from `DNSTransaction` | `dns.FilterAndDedupRecords`, `dns.SortOutputRecords`, `output.WriteTable`, `output.WriteJSON`, `output.WriteCSV`, table stats | No field mutation after creation; slice order changes in `SortOutputRecords` | contract-bearing | Main table semantics depend on earlier `DNSTransaction` mutation and later filtering by `DestinationPort`. |
| `TopologyEntry` | `internal/dns/network_topology_matrix.go` | Final issuer -> destination -> DNS attribution row. | `dns.BuildNetworkTopologyMatrixEntriesWithOptions`, optionally `dns.SquashNetworkTopologyShortWithOptions` | topology writers, service endpoint builder, unresolved endpoint builder, external endpoint builder, unresolved-DNS filter | Yes, inside `BuildNetworkTopologyMatrixEntriesWithOptions` while refining local output rows | contract-bearing | This is the highest-risk output type because many heuristics terminate here. |
| `ServiceEndpoint` | `internal/dns/service_endpoints.go` | Stable endpoint export row for downstream ingestion. | `dns.BuildServiceEndpoints` from `TopologyEntry` | `output.WriteServiceEndpointsJSON` | No after final slice creation | contract-bearing | Uses synthetic DNS placeholders when no real DNS exists for an endpoint tuple. |
| `DNSUnresolvedStat` | `internal/dns/stats.go` | Row for unresolved DNS-name reporting. | `dns.ComputeUnresolvedDNSFirstSeen`, also `buildUnresolvedStatsFromTxs` in active resolve path | `dns.FilterUnresolvedByTopologyAttribution`, `output.WriteUnresolvedDNSTable` | No | contract-bearing | Meaning is global-by-name with issuer context, not a raw transaction dump. |
| `UnresolvedIPEndpoint` | `internal/dns/unresolved_ip.go` | Row for unresolved public destination endpoints. | `dns.PublicUnresolvedDestinationEndpoints` from final `TopologyEntry` slice | `dns.WriteUnresolvedIPEndpointsJSON` | No | contract-bearing | Only public unresolved endpoints survive into this artifact. |
| `IPDNSPair` | `internal/dns/dns_ip_file.go` | DNS/IP pair persisted into the fallback CSV map. | `dns.MergeIPToDNSMaps` after `dns.StrongObservedIPDNSPairsFromTransactions` | `dns.AppendIPDNSPairsToFile`, `dns.BuildIPDNSAppendAuditRecords` | No | contract-bearing | Persisted side effect, so it affects future runs as well as the current one. |

## Working, Heuristic, And Intermediate Types

| name | package / file | purpose | produced by | consumed by | mutated? yes/no and where | contract importance | risk / notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `OutputManager` | `cmd/output_manager.go` | Run-scoped owner of output directory paths and file creation. | `cmd.NewOutputManager` | all file-writing and manifest-writing steps | No after construction | intermediate | Operational state, not a data contract, but path/layout decisions are externally visible. |
| `DNSTransaction` | `internal/dns/types.go` | Canonical in-memory DNS/SNI working record. | `dnsExtractor.OnPacket`, `sniExtractor.OnPacket`, also legacy `BuildTransactionsFromEvents` and `BuildSNITransactionsFromPCAPs` | active resolve, correlation, topology builder, output record builder, stats/report builders | Yes; heavily mutated by `AddResolvedIP`, `MarkObservedConn`, `mergeDNSTransaction`, `ResolveUnresolvedDNSTransactions`, `AttachConnectionsAndCollectEdgesFromPCAPs`, and issuer-label assignment in `runDNSExtract` | heuristic-state | Most central mutable type in the repo. |
| `TxKey` | `internal/dns/types.go` | Pass-2 key for query/response bucketing and merge. | DNS query extraction in `extractors.go` and `from_pcap.go` | per-file/global maps inside `BuildTransactionsWithSNIFromPCAPs` and legacy scan helpers | No | intermediate | Current hot-path query/response key. Distinct from legacy `txKey` in `correlate.go`. |
| `ConnCandidate` | `internal/dns/types.go` | Temporary candidate connection for one DNS transaction. | `AttachConnectionsAndCollectEdgesFromPCAPs` | `pickBestCandidate`, then collapsed into `DNSTransaction.DestinationPort` / `ProtocolL4` | Yes; appended to `DNSTransaction.Candidates` then discarded | heuristic-state | Small type with large downstream effect on whether a row is considered connected. |
| `Evidence` | `internal/dns/evidence.go` | Bitmask describing how a name/IP association was obtained. | DNS response parsing, SNI synthesis, active resolve, observed-connection marking | `ToOutputRecords`, topology builder, audit builder, tests | Yes; OR-ed into `DNSTransaction.ResolvedIPEvidence` and normalized in helper code | heuristic-state | Central to source labels. CSV fallback in topology bypasses this type and writes source strings directly. |
| `FirstPacketInfo` | `internal/dns/from_pcap.go` | Earliest packet metadata seen during correlation scan. | `AttachConnectionsAndCollectEdgesFromPCAPs` | manifest writing, IP/DNS append audit writing | No after return | intermediate | Metadata carrier only, but it feeds the manifest contract. |
| `Edge` | `internal/connectivity/collector.go` | Observed `(issuer,dst,proto,port,firstSeen)` connectivity fact. | `connectivity.Collector.Edges` / `EdgesByFirstSeen`, aggregated by `AttachConnectionsAndCollectEdgesFromPCAPs` | topology builder, FTP suppression helper, tests | No after creation/aggregation | intermediate | Bridge from packet observation to topology attribution. |
| `SessionWindow` | `internal/radius/radius_session_builder.go` | Time window of IP ownership for `(IMSI, IP, SessionID)`. | `sessionBuilder.ingest`, `finalizeForReplay`, `closedCoalesced` | `BuildIMSIIndexFromPCAPs`, then `IMSIIndex.Lookup` | Yes; mutated inside `sessionBuilder` as accounting messages arrive | heuristic-state | Optional branch, but it changes issuer identity semantics, not just cosmetics. |
| `IMSIIndex` | `internal/radius/index.go` | Time-aware IP -> IMSI lookup structure. | `BuildIMSIIndexFromPCAPs` | issuer-label mutation in `runDNSExtract`, topology `issuerFn` | Yes during build; effectively read-only after return | heuristic-state | Empty index is a valid degraded result. |

## Types That Look Legacy, Duplicated, Or Ambiguous

- `internal/pcap.Event` and `dns.txKey` support the older `BuildTransactionsFromEvents` / `AttachConnections` flow. They do not appear on the current `dnsextract` hot path.
- `BuildSNITransactionsFromPCAPs` in `internal/dns/from_tls.go` produces synthetic `DNSTransaction` values too, which overlaps with the active `sniExtractor` path in `extractors.go` and `from_pcap_names.go`.
- Those two SNI-producing paths populate `DNSTransaction` differently: `from_tls.go` sets `NameEvidence: EvSNI`, while the active `sniExtractor` path does not currently do so.
- `BuildNameIPEvidenceIndex` and `NameIPSourceLabel` in `internal/dns/name_ip_evidence_index.go` look current, but they are not referenced on the active runtime path inspected in this pass.
- `internal/dns.L4Proto` and `internal/connectivity.L4Proto` represent the same domain concept with separate package-local types.

## Open Questions For The Next Pass

- Should the older event-based flow be treated as dormant legacy or as a secondary supported path?
- Is `from_tls.go` still meant to be authoritative anywhere, or has `BuildTransactionsWithSNIFromPCAPs` fully replaced it?
- Are the unused evidence-index helpers intentionally reserved for future output work, or are they stale code?
