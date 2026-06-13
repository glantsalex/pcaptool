# Heuristics Catalog

Scope: active-path heuristics in `pcaptool dnsextract` only. Legacy helpers such as `internal/pcap.Event`, `dns.BuildTransactionsFromEvents`, and `dns.AttachConnections` are intentionally excluded except where ambiguity matters.

## Direct Parsing Behavior

### 1. Truncated DNS salvage

- `name`: Truncated DNS query/response salvage
- `package/file/function(s)`: `internal/dns/extractors.go`
  - `dnsExtractor.OnPacket`
  - `extractDNSQueryNameFromRaw`
  - `extractDNSResponseFromRaw`
- `purpose`: Recover partial DNS evidence from snaplen-truncated DNS packets instead of dropping them outright.
- `evidence used`: raw UDP/TCP DNS payload bytes, packet truncation metadata, DNS header fields, query/answer sections when available.
- `decision / fallback rule`:
  - only A-type queries are accepted
  - raw salvage is attempted only when packet metadata indicates truncation or DNS parsing is incomplete
  - partial names may be accepted; malformed or non-A payloads are rejected
- `downstream effect`:
  - can create or enrich `DNSTransaction`
  - influences `OutputRecord`, `TopologyEntry`, unresolved DNS reporting, and learned IP->DNS persistence later in the run
- `risk notes`:
  - too permissive: invents names/IPs from malformed payloads
  - too strict: loses evidence in exactly the truncated-capture cases this tool is built for
  - regression anchors: `internal/dns/extractors_truncated_test.go`

### 2. TLS SNI extraction gating

- `name`: Full-ClientHello-only SNI extraction
- `package/file/function(s)`: `internal/dns/tls_sni.go`, `internal/dns/extractors.go`
  - `extractSNIFromClientHello`
  - `sniExtractor.OnPacket`
- `purpose`: Derive name evidence from TLS ClientHello when DNS answers are missing.
- `evidence used`: non-truncated TCP payload containing a complete TLS ClientHello `server_name` extension.
- `decision / fallback rule`:
  - only complete, in-payload ClientHello records are parsed
  - truncated or split TLS records are ignored instead of guessed
- `downstream effect`:
  - creates synthetic `DNSTransaction`
  - influences `TopologyEntry` source precedence and final naming when SNI is the only available name evidence
- `risk notes`:
  - conservative by design; prefers missing SNI over speculative parsing
  - active-path ambiguity remains: `sniExtractor` and `from_tls.go` do not initialize `DNSTransaction` identically

### 3. Name suppression filters

- `name`: NTP/time-sync filtering and resolvable-name gating
- `package/file/function(s)`:
  - `internal/dns/ntp_filter.go`
    - `LooksLikeNTPDNSName`
    - `FilterOutNTPDNSTransactions`
  - `internal/dns/name_heuristics.go`
    - `LooksLikeResolvableDNSName`
  - `internal/dns/unresolved_resolver.go`
    - `IsResolvableDNSName`
- `purpose`: Drop or skip names that are low-value or unsafe for correlation / active resolution.
- `evidence used`: DNS name shape only.
- `decision / fallback rule`:
  - NTP-like DNS names are dropped by default, except SNI-derived names
  - non-FQDN-ish names, `.local`, `.lan`, underscore-heavy names, and similar low-confidence labels are not used for inference or active resolve
- `downstream effect`:
  - reduces `DNSTransaction` set before correlation
  - influences unresolved reporting, active resolution coverage, and any later attribution that depends on candidate names
- `risk notes`:
  - conservative behavior protects against noisy inference
  - wrong patterns can either hide legitimate services or let device-local garbage contaminate attribution
  - regression anchors: `internal/dns/ntp_filter_test.go`

## Conservative Correlation Behavior

### 4. Connectivity edge confirmation and direction heuristics

- `name`: Observed edge construction
- `package/file/function(s)`: `internal/connectivity/collector.go`
  - `Collector.OnPacket`
  - `onTCP`
  - `onUDP`
  - `observeFTPPassiveControl`
- `purpose`: Turn packet sequences into observed `(issuer,dst,proto,port,firstSeen)` edges for later attribution.
- `evidence used`: TCP SYN/SYN-ACK, UDP request/reply symmetry, private/public directionality, excluded port sets, FTP control/data semantics.
- `decision / fallback rule`:
  - TCP prefers SYN/SYN-ACK confirmation, with limited mid-session admission
  - UDP requires symmetric observation and can enforce “private is source”
  - excluded service ports suppress candidate edges
  - FTP passive data ports are suppressed when they look like control-derived artifacts
- `downstream effect`:
  - produces `[]connectivity.Edge`
  - directly shapes `TopologyEntry`, unresolved endpoint output, and service-endpoint derivation
- `risk notes`:
  - this is still “parsing-like” but already policy-bearing because direction and suppression decisions determine what later becomes attributable
  - regression anchors: `internal/connectivity/collector_test.go`, `internal/dns/from_pcap_test.go`

### 5. Conservative DNS-to-connection matching

- `name`: Direct match, windowed fallback, and candidate selection
- `package/file/function(s)`: `internal/dns/from_pcap.go`
  - `AttachConnectionsAndCollectEdgesFromPCAPs`
  - `BuildTxnIndex`
  - `findLatestTxBefore`
  - `pickFallbackTxUniq`
  - `pickBestCandidate`
- `purpose`: Attach connectivity back to DNS transactions without over-attributing.
- `evidence used`:
  - `(issuer,dst)` transaction index
  - request time vs connection time
  - `LooksLikeResolvableDNSName`
  - protocol and selected-port compatibility
- `decision / fallback rule`:
  - direct `(issuer,dst)` lookup wins
  - issuer-only fallback is TCP-only and only allowed when exactly one unresolved candidate exists in the time window
  - UDP issuer-only fallback is explicitly disabled
  - candidates outside `maxConnDelay` are discarded
  - final candidate is the minimum-time-delta match, optionally filtered by `--only-tcp`
- `downstream effect`:
  - mutates `DNSTransaction` with `Candidates`, `DestinationPort`, `ProtocolL4`, and observed-connection evidence
  - influences main DNS table, topology attribution, service endpoints, unresolved outputs, and learned fallback-map persistence
- `risk notes`:
  - strongly conservative; ambiguity usually means “drop the candidate”
  - incorrect relaxation here causes the broadest semantic contamination in the repo
  - regression anchors: `internal/dns/from_pcap_test.go`

### 6. CSV guard on inferred backfill

- `name`: Inference veto against fallback map
- `package/file/function(s)`: `internal/dns/from_pcap.go`
  - `allowConnectionInferredDNSBackfill`
- `purpose`: Prevent issuer-only TCP fallback from backfilling a destination IP into the wrong DNS name when CSV already suggests a conflicting mapping.
- `evidence used`: candidate DNS name plus loaded `ipToDNS` CSV map.
- `decision / fallback rule`:
  - no CSV entry: allow inference
  - exact CSV name match: allow inference
  - single different CSV name: veto inference
  - multi-name CSV without the candidate: veto inference without choosing a replacement name
- `downstream effect`:
  - suppresses mutation of `DNSTransaction.ResolvedIPs` and `ResolvedIPEvidence`
  - indirectly affects topology and learned fallback-map updates
- `risk notes`:
  - conservative override; it prefers dropping inferred connectivity over forcing a CSV-based rename at this stage
  - regression anchors: `internal/dns/from_pcap_test.go`

## Fallback Attribution Behavior

### 7. Active unresolved-name resolution

- `name`: Controlled active resolve
- `package/file/function(s)`: `internal/dns/unresolved_resolver.go`
  - `ResolveUnresolvedDNSTransactions`
  - `DefaultResolveUnresolvedOptions`
  - `IsResolvableDNSName`
- `purpose`: Optionally inject IPv4 evidence for still-unresolved names.
- `evidence used`: unresolved `DNSTransaction` set, resolvable-name filter, external resolver responses.
- `decision / fallback rule`:
  - only names that pass the real-FQDN filter are queried
  - IPv4 only
  - per-name failures degrade to unresolved output; they do not abort the run
  - injected IPs are marked `EvActiveResolve`
- `downstream effect`:
  - mutates `DNSTransaction`
  - can change main table rows, topology attribution, unresolved reports, and source labels
- `risk notes`:
  - opportunistic behavior gated behind a flag
  - little targeted test coverage was visible in this pass; treat this as a weaker safety zone than the topology or correlation logic

### 8. Topology join, fallback, and precedence

- `name`: Final topology attribution engine
- `package/file/function(s)`: `internal/dns/network_topology_matrix.go`
  - `BuildNetworkTopologyMatrixEntriesWithOptions`
  - `csvNameForIP`
  - `SquashNetworkTopologyShortWithOptions`
- `purpose`: Convert edges plus transaction evidence into final issuer-to-destination rows.
- `evidence used`:
  - `DNSTransaction` buckets keyed by `(issuer,dstIP)`
  - `Edge.FirstSeen`
  - `Evidence` labels
  - `TopologyBuildOptions.MaxDNSAge`
  - optional CSV map
  - optional issuer relabeling callback
- `decision / fallback rule`:
  - hard exclusions first: DNS transport ports and resolver-originated edges are removed
  - private destinations never receive inferred DNS
  - best in-window transaction match wins using protocol/port compatibility scoring
  - if no transaction matches:
    - private issuer -> public destination can use `csv+mid` or unresolved `mid-session`
    - otherwise can use `csv+conn` or remain unresolved
  - final CSV check can upgrade unresolved public rows if the IP has exactly one CSV name
  - unresolved rows are suppressed when a DNS-attributed row exists for the same tuple
  - strong DNS evidence suppresses weaker CSV fallback
  - peer completion can fill unresolved rows from unique donor names on the same endpoint tuple
- `downstream effect`:
  - produces `TopologyEntry`
  - shapes `network-topology-matrix.*`, `service-endpoints.txt`, `external-endpoints.txt`, `dns-unresolved-dns.txt`, and `unresolved-ip.json`
- `risk notes`:
  - mix of conservative and opportunistic rules:
    - conservative: private destinations unnamed, ambiguous CSV rejected, conflicting CSV downgraded, unresolved rows preserved
    - opportunistic: peer completion, mid-session CSV, final CSV check
  - precedence rules are dense and test-anchored
  - regression anchors: `internal/dns/network_topology_matrix_test.go`, `output/connectivity_matrix_test.go`, `internal/dns/unresolved_stats_test.go`, `internal/dns/service_endpoints_test.go`

## Persistence / Replay Behavior

### 9. Learned fallback-map persistence

- `name`: Strong observation learning and CSV merge
- `package/file/function(s)`: `internal/dns/dns_ip_file.go`, `internal/dns/ip_dns_audit.go`
  - `LoadIPToDNSFromFile`
  - `StrongObservedIPDNSPairsFromTransactions`
  - `MergeIPToDNSMaps`
  - `AppendIPDNSPairsToFile`
  - `BuildIPDNSAppendAuditRecords`
- `purpose`: Reuse prior IP->DNS knowledge and optionally extend it with high-confidence observations from the current run.
- `evidence used`:
  - CSV file contents
  - only `dns+synack`-strength observations from `DNSTransaction`
  - earliest strong provenance for audit output
- `decision / fallback rule`:
  - CSV load is flexible on input format but canonicalizes to IPv4 + lowercase DNS
  - only previously unseen IPs are learned
  - learned names must be public, direct DNS-answer-backed, and observed by connection
  - `EvConnInferred`, SNI-only, and private-IP observations are not persisted
  - one deterministic representative DNS name is chosen per learned IP
- `downstream effect`:
  - changes current-run fallback behavior after merge
  - appends durable state for future runs
  - can emit `ip-dns-append-audit.txt`
- `risk notes`:
  - this is the replay-sensitive family: a mistake here survives the current invocation
  - regression anchors: `internal/dns/dns_ip_file_update_test.go`, `internal/dns/ip_dns_audit_test.go`, `output/ip_dns_audit_test.go`

## Identity Relabeling Behavior

### 10. RADIUS session-window identity mapping

- `name`: Time-aware IMSI relabeling
- `package/file/function(s)`: `internal/radius/index.go`, `internal/radius/radius_session_builder.go`
  - `BuildIMSIIndexFromPCAPs`
  - `sessionBuilder.ingest`
  - `finalizeForReplay`
  - `IMSIIndex.Lookup`
- `purpose`: Replace issuer IP labels with IMSI labels when RADIUS Accounting traffic supports that mapping.
- `evidence used`: RADIUS Start / Interim / Stop messages, IP, IMSI, SessionID, session duration, timestamp ordering.
- `decision / fallback rule`:
  - synthetic opens can be created from Interim/Stop
  - new Start can close older open sessions for the same `(IMSI,IP)` pair
  - coalesced time windows are used for lookup
  - lookup failures degrade to the raw issuer IP label
- `downstream effect`:
  - mutates `DNSTransaction.IssuerLabel`
  - changes `OutputRecord.IssuerIP`, `TopologyEntry.IssuerIP`, and derived reports grouped by issuer
- `risk notes`:
  - optional feature, but semantically important because it changes identity, grouping, and rollups
  - targeted tests were not evident in this pass; treat changes here as high-risk and under-tested

## Precedence And Behavior Summary

- Conservative by design:
  - truncated DNS is salvaged only with bounds-checked raw parsing
  - UDP issuer-only fallback is disabled
  - private destinations are never given inferred DNS
  - ambiguous CSV mappings are rejected
  - unresolved rows are preserved when no safe attribution exists
  - learned CSV persistence excludes inferred, SNI-only, and private-IP evidence
- Opportunistic, but bounded:
  - active resolve can inject IPs for resolvable unresolved names
  - `csv+mid` and `csv+conn` can fill topology rows when direct evidence is absent
  - peer completion can backfill unresolved rows only from unique donor names
- Key precedence rules:
  - direct match beats issuer-only fallback
  - strong DNS evidence beats CSV fallback
  - unique donor peer completion beats leaving a public endpoint unresolved, but ambiguity cancels the donor

## Remaining Ambiguities

- `internal/dns/from_tls.go` overlaps with the active `sniExtractor` path and initializes SNI transactions differently.
- `internal/dns/name_ip_evidence_index.go` appears unused on the current hot path.
- RADIUS identity logic appears active and important, but dedicated tests were not obvious in this onboarding pass.
