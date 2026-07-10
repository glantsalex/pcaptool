# DNS Attribution Pipeline Review

This note documents how `pcaptool dnsextract` currently processes DNS traffic and uses DNS-derived evidence to label rows in the network topology matrix.

It is based on the current code paths in `cmd/dnsextract.go` and `internal/dns/*`. The focus is attribution quality, especially cases where query-only DNS evidence can become `dns+conn+synack`.

## 1. Entry points

The CLI entry point is `runDNSExtract` in `cmd/dnsextract.go`.

High-level runtime order:

1. Parse CLI flags and resolve input PCAP files.
2. Load `dns-ip.csv` through `internal/dns.LoadIPToDNSFromFile`.
3. Optionally merge `topology-{net-id}.csv` as an in-memory DNS/IP overlay.
4. Parse DNS/SNI transactions with `dns.BuildTransactionsWithSNIFromPCAPsWithDiagnostics`.
5. Correlate transactions with observed connectivity using `dns.AttachConnectionsAndCollectEdgesFromPCAPs`.
6. Append newly learned strong DNS/IP pairs to `dns-ip.csv` when enabled.
7. Build topology rows with `dns.BuildNetworkTopologyMatrixEntriesWithOptions`.
8. Apply post-matrix completion passes:
   - active DNS completion, when `--active-resolve` is enabled;
   - exact endpoint donation, `donated+ipport` / `donated+ipport+conn`;
   - reverse DNS completion, when `--reverse-dns-lookup` is enabled;
   - TLS certificate SAN completion, when `--tls-cert-lookup` is enabled.
9. Write matrix, DNS, diagnostic, fleet, and manifest artifacts.

Important DNS-related flags:

- `--dns-ip-file`: input/output CSV cache of DNS/IP pairs.
- `--topology-dns-window`: max age for joining DNS evidence to topology edges during matrix build. This is not the initial query-only fallback window.
- `--active-resolve`: active A lookup for unresolved names, used only as weak post-matrix completion.
- `--reverse-dns-lookup`: PTR/reverse-DNS lookup for unresolved public IPv4 destinations.
- `--reverse-dns-resolver`: optional resolver for reverse DNS only.
- `--tls-cert-lookup`: active TLS certificate probing for unresolved public TCP endpoints.
- `--tls-cert-lookup-timeout`: per-endpoint TCP connect plus TLS handshake timeout.
- `--debug`: gates some diagnostic artifacts, including truncated DNS diagnostics in the current implementation.
- `--disable-sni`: disables SNI extraction and changes the BPF filter so only UDP DNS is scanned.

## 2. Packet-level DNS parsing

The main scanner is in `internal/dns/from_pcap_names.go`, which calls the DNS and SNI extractors over each input file.

DNS parsing is primarily in `internal/dns/extractors.go`:

- `dnsExtractor.OnPacket` handles packet-level DNS parsing.
- UDP DNS payloads are parsed directly.
- TCP DNS payloads are parsed only when the packet payload contains a DNS length prefix and a complete DNS message in that packet. There is no TCP stream reassembly.
- With SNI enabled, the scan filter includes `udp port 53 or tcp`; with SNI disabled, it uses only `udp port 53`.

DNS transaction state is held in `DNSTransaction` in `internal/dns/types.go`.

The transaction key type is `TxKey`:

- issuer IP;
- DNS client source port;
- resolver IP;
- L4 protocol;
- DNS transaction ID;
- DNS query name.

Response lookup uses a response-side key without the name, then `pickResponseTx` chooses the matching query transaction. The preferred match is the newest prior query whose requested name exactly matches the response name; otherwise the newest prior query with the same tuple and DNS ID can be used.

DNS state is per scanner/file pass. A query in one PCAP file is not matched to a response in another PCAP file.

Currently extracted DNS record behavior:

- Queries: only first question is used for normal transactions.
- Query type: normal DNS transactions are created for A queries.
- Answers: A records are extracted from the answer section.
- CNAME records are not explicitly parsed into alias chains.
- AAAA, PTR, TTL, additional records, and authority records are not used for normal DNS/IP attribution.

## 3. Handling DNS responses

When a DNS response is matched to a query transaction:

- A answer IPs are added as resolved IPs on the transaction.
- The owner name of the A answer is not used as a separate canonical identity for the mapping.
- Multiple A records for a response become multiple resolved IPs on the same original query name.
- TTL is not stored or enforced.
- Response timestamp is stored through transaction timing fields.
- Resolver IP is part of the transaction tuple.
- The issuer/device IP comes from the client side of the DNS query.

CNAME handling is limited:

- There is no dedicated CNAME field in `DNSTransaction`.
- There is no alias-chain resolution.
- If a response contains `alias.example CNAME canonical.example` plus `canonical.example A 1.2.3.4`, the A record can be attached to the original query transaction because the parser collects A answers.
- If a response contains only CNAME records and no A records, the query remains unresolved from the perspective of DNS/IP mapping.

Unsolicited responses or responses whose original query was not seen generally cannot create a normal DNS transaction, because matching depends on an existing query transaction.

## 4. Handling DNS queries without usable responses

Query-only DNS evidence is stored as a transaction with a DNS name but no resolved IPs.

That query-only evidence can later be connected to observed traffic by `AttachConnectionsAndCollectEdgesFromPCAPs` in `internal/dns/from_pcap.go`.

The important fallback path is:

1. A DNS A query exists for an issuer, but has no resolved IP.
2. The same issuer later opens an observed outbound TCP connection.
3. There is no exact transaction match for the destination IP.
4. The fallback search finds exactly one eligible unresolved query for that issuer in a hard-coded recent time window.
5. The observed destination IP is added to that DNS transaction as inferred connectivity evidence.

This is the path that can result in `dns+conn+synack`.

The source label is misleadingly strong: it means “DNS name from packet evidence plus inferred connection IP,” not necessarily “DNS response proved this name resolved to this IP.”

## 5. Truncated DNS packets

Truncated DNS diagnostics are handled during packet parsing. The code can recover partial QNAMEs from raw bytes when a DNS query was truncated by capture snaplen or malformed enough that normal parsing cannot recover a complete name.

Current behavior:

- The diagnostic artifact is `truncated-dns-packets.csv`.
- It records partial/recovered names and packet metadata.
- It is currently debug-gated in the command layer.
- Truncated names are excluded from `dns-unresolved-dns.txt` by using the in-memory diagnostics, even when the artifact itself is not written.

The diagnostic detects raw DNS query name truncation cases such as:

- label length says more bytes should exist than are captured;
- missing root label;
- unsupported compression pointer in a query-name recovery path.

It is not simply the DNS TC bit. It is mostly capture/payload-level incomplete-name detection.

Important consequences:

- A truncated DNS query diagnostic should not create a `DNSTransaction`.
- A truncated partial DNS name should not be used for DNS attribution.
- A truncated response can still produce mappings if the parser can decode usable complete A answers.
- Low-snaplen PCAPs are high risk because complete responses may be missing while query-only fallback remains possible.

## 6. DNS-to-connection correlation

The main correlation path is `AttachConnectionsAndCollectEdgesFromPCAPs` in `internal/dns/from_pcap.go`.

### `dns+synack`

This is produced when topology evidence includes direct DNS answer evidence for the destination IP plus observed connection evidence.

Required evidence:

- DNS transaction with resolved destination IP from a DNS answer.
- Topology edge for the same issuer/destination/protocol/port within the matrix DNS age window.
- Observed connection evidence on the edge.

Despite the label, the DNS transaction correlation itself is not strictly a SYN-ACK matcher. The connectivity edge collector can track SYN/SYN-ACK, but the transaction enrichment path marks observed connection evidence from outbound connection-like packets.

### `dns+conn+synack`

This is produced when the transaction has DNS name evidence and the destination IP was added through inferred connectivity.

The critical path is:

- `pickFallbackTxUniq` searches unresolved query-only transactions for the same issuer.
- The hard-coded fallback window is `maxConnDelay = 5 * time.Second`.
- If exactly one unresolved eligible transaction is found, the later destination IP can be added to that transaction with `EvConnInferred | EvObservedConn`.
- Matrix output converts that evidence set into `dns+conn+synack`.

This does not require a DNS answer mapping the DNS name to that IP.

This is the main known misattribution risk:

- Device queries `www.cisco.com`.
- DNS response is missing or truncated.
- Device later connects to an unrelated AWS/S3 IP inside the fallback window.
- If the Cisco query is the only eligible unresolved query, the AWS IP may become associated with `www.cisco.com`.

### `csv+mid`

This is produced when no DNS transaction is selected for a private-to-public edge, but `dns-ip.csv` / topology overlay has exactly one canonical DNS name for the destination IP.

The row remains weak because the CSV mapping is external/cache evidence, not packet-time DNS evidence for the observed connection.

### `mid-session`

This is the fallback label when a matrix edge exists but no DNS/SNI/CSV/active/PTR/TLS/donation attribution is selected.

It does not necessarily prove the capture missed the TCP handshake. It primarily means no usable DNS label was attached to that topology row.

### Other matrix completion labels

- `active+matrix`: optional active A lookup completed an unresolved public matrix row.
- `ptr+matrix`: reverse DNS gave a usable raw PTR label.
- `ptr+fcrdns+matrix`: reverse DNS PTR was forward-confirmed to the same IP.
- `ptr-normalized+matrix`: provider-generated PTR was normalized, for example AWS EC2 IP-encoded names.
- `tls-cert-san+matrix`: TLS certificate probing selected a SAN/CN from the exact row endpoint.
- `tls-cert-san+matrix-fallback`: TLS certificate probing selected a SAN/CN from fallback port 443 or 8443 for that IP.
- `donated+ipport`: row inherited direct DNS/SNI evidence from another issuer on the exact same destination IP/protocol/port.
- `donated+ipport+conn`: row inherited inferred `dns+conn+synack` evidence from another issuer on the exact same destination IP/protocol/port.

## 7. SYN/SYN-ACK and connection evidence

TCP connection evidence is collected from packet-level TCP flags.

The code distinguishes:

- outbound SYN-like connection starts;
- SYN-ACK-confirmed edges in connectivity collection;
- mid-session private-to-public packets when a full handshake is not visible;
- UDP edge observations.

Connection/topology edge identity is keyed by:

- issuer IP;
- destination IP;
- protocol;
- destination port;
- timing metadata.

DNS transaction enrichment and topology edge collection are related but separate. This is why a label containing `synack` should not be interpreted as a perfect guarantee that the DNS transaction itself was matched against a fully verified SYN/SYN-ACK exchange.

A row can still be labelled `mid-session` even when SYN/SYN-ACK packets exist somewhere in the PCAP if those packets were not matched into that exact topology row or no DNS attribution was selected for that row.

## 8. `dns-ip.csv` usage

`dns-ip.csv` is both an input cache and, when enabled, an output/update target.

Loader behavior is implemented in `internal/dns/dns_ip_file.go`:

- `LoadIPToDNSFromFile` supports both `dns,ip` and `ip,dns` rows.
- It canonicalizes DNS names and IPv4 strings.
- IPv6 rows are not used by the matrix CSV fallback path.
- Duplicate names are deduped per IP.

Topology overlay behavior:

- If `dns-ip.csv` is loaded and a sibling `topology-{net-id}.csv` exists, it can be merged as an in-memory overlay.
- Overlay format is strict `dns,ip`.
- Base `dns-ip.csv` wins.
- First overlay row wins for an IP.
- The overlay is not written back.

Write/update behavior:

- `StrongObservedIPDNSPairsFromTransactions` extracts only strong observed packet pairs.
- Pairs with `EvConnInferred` are not persisted.
- Active DNS, PTR, TLS certificate, and donation completions are not written to `dns-ip.csv`.

Conflict behavior:

- If a destination IP has exactly one canonical CSV DNS name, it can be used as `csv+mid`.
- If multiple names exist for an IP, the CSV fallback is ambiguous and should not choose an arbitrary name.
- CSV does not store source, timestamps, TTL, resolver, or confidence.

## 9. Network topology matrix attribution selection

Topology matrix rows are built in `BuildNetworkTopologyMatrixEntriesWithOptions` in `internal/dns/network_topology_matrix.go`.

The connectivity edge key is effectively:

- issuer IP;
- destination IP;
- protocol;
- destination port.

The emitted row key includes the DNS name, so the matrix can contain multiple rows for the same endpoint when different names are selected.

Selection behavior:

- The matrix builds transaction indexes by issuer and destination IP.
- It searches for the best transaction within `MaxDNSAge`, which is controlled by `--topology-dns-window`.
- Candidate scoring considers protocol/port compatibility and timing.
- There is not a simple global source-confidence ranking across every source.
- If no transaction is found, CSV fallback or `mid-session` may be used.

Important distinction:

- `--topology-dns-window` applies during topology row selection.
- The query-only fallback that can create `dns+conn+synack` uses a separate hard-coded 5 second window earlier in the pipeline.

## 10. Peer/donated attribution

Donation is implemented in `CompleteTopologyWithDNSDonation` in `internal/dns/network_topology_matrix.go`.

Donation key:

- normalized destination IPv4;
- normalized protocol;
- destination port.

Recipient rule:

- destination IP must be public IPv4;
- `DNSName` must be empty or whitespace;
- `DNSSource` must be empty or `mid-session`;
- exact destination tuple must match.

Direct donors:

- `dns+synack`;
- `sni+synack`.

Inferred donors:

- `dns+conn+synack`.

Rejected donors include:

- `csv+mid`;
- PTR labels;
- TLS certificate labels;
- active labels;
- previous donation labels;
- `mid-session`;
- blank or unknown sources.

Priority:

1. Direct donors win.
2. Inferred donors are used only if no direct donors exist.
3. Direct and inferred names are never mixed for a single donation decision.

Ambiguity behavior:

- If there is one normalized donor name, donate that name.
- If there are multiple names, compute the longest common DNS suffix from the TLD side.
- The suffix must contain at least two labels.
- Example: `evse.total-ev-charge.com` and `evse-psa.total-ev-charge.com` collapse to `total-ev-charge.com`.

Donation affects the matrix entries before text, JSON, compact JSON, and derived outputs are written.

## 11. Failure modes and misattribution risks

### Query without actual connection to that DNS service

Current code can allow this through query-only fallback. A query-only transaction can absorb a later unrelated destination IP if it is the only eligible unresolved transaction in the issuer fallback window.

Mitigation is partial: `pickFallbackTxUniq` requires uniqueness among eligible unresolved queries, but it does not prove the destination IP belongs to the queried DNS name.

### `www.cisco.com` attached to AWS/S3 IP

This is allowed by the current `dns+conn+synack` path when the DNS response is missing/incomplete and the unrelated connection falls inside the fallback window.

If `dns+conn+synack` is later allowed to donate, the bad association can propagate across issuers on the same endpoint.

### Missing or truncated DNS response

If an answer is missing, direct DNS/IP evidence is unavailable. Query-only fallback can still infer a destination IP, which is risky.

If a response is truncated but still contains decodable A records, mappings can still be produced.

### Multiple DNS queries close together

The fallback uniqueness guard helps if multiple unresolved eligible queries exist. But if only one remains eligible, it can still be wrongly attached.

### Multiple SYNs close together

One unresolved query can be associated with multiple observed destination IPs over time if each update passes the fallback logic. This can produce one DNS name mapped to many IPs without DNS answers.

### CDN/cloud IPs

CSV, PTR, TLS, active DNS, and query-only fallback all have cache/time/tenant ambiguity risks. The current matrix source label is the main confidence indicator.

### Same IP, different ports

Donation keys include port and protocol. TLS certificate probing now caches by IP plus probe port and distinguishes exact endpoint labels from fallback labels.

### Stale `dns-ip.csv`

CSV can label unresolved rows as `csv+mid`. It does not override direct packet evidence in normal selection, but stale CSV can still create misleading weak labels.

### PTR fallback

PTR completion is explicitly weak endpoint labeling. It may produce infrastructure names rather than service names.

### Cross-device donor propagation

Donation is restricted to exact destination IP/protocol/port, but inferred donation from `dns+conn+synack` can still spread an already-wrong inferred mapping.

## 12. Current time windows and constants

Relevant windows and defaults:

- Query-only DNS-to-connection fallback:
  - `maxConnDelay = 5 * time.Second` in `internal/dns/from_pcap.go`.
  - Hard-coded.
  - Not controlled by `--topology-dns-window`.

- Topology DNS age:
  - `--topology-dns-window`.
  - Default documented as `2m`.
  - Controls how old DNS evidence may be when selecting matrix attribution.

- Reverse DNS lookup:
  - Per-IP timeout documented as two seconds.
  - Controlled internally; resolver can be changed with `--reverse-dns-resolver`.

- TLS certificate lookup:
  - `--tls-cert-lookup-timeout`.
  - Default 15 seconds.
  - Valid integer range 5 to 30 seconds.
  - Covers TCP connect plus TLS handshake/certificate extraction.

- Active resolve:
  - Runs concurrently through active resolver logic.
  - Used only for weak post-matrix completion.

## 13. Artifacts and auditability

Artifacts useful for DNS attribution debugging:

- `dns-ip.csv`
  - Contains DNS/IP pairs only.
  - No source, time, TTL, or confidence.
  - Does not include inferred `dns+conn+synack` pairs.

- `dns-unresolved-dns.txt`
  - Contains unresolved complete DNS names after filtering.
  - Truncated diagnostic names are excluded.
  - CNAME-resolved aliases are excluded when resolved-name logic identifies them.

- `truncated-dns-packets.csv`
  - Contains truncated DNS query diagnostics when written.
  - Useful for low-snaplen PCAP analysis.

- `reverse-dns-lookup-log.csv`
  - Written when reverse DNS lookup is enabled.
  - Includes PTR status, selected name, source, resolver, forward-confirmation details, and errors.

- `tls-cert-lookup-log.csv`
  - Written when TLS certificate lookup is enabled.
  - Includes endpoint, selected certificate name, source, reason, SANs, CN, issuer, validity, and errors.

- `network-topology-matrix.txt/json/compact.json`
  - Shows final label and `DNSSource`.
  - Does not explain every candidate considered.

- `unique-dns-port-proto.csv`
  - Derived from the final matrix.
  - Useful for service summaries, not attribution debugging.

- `ip-dns-append-audit.txt`
  - Debug-only audit for appending strong pairs to `dns-ip.csv`.
  - Does not explain `dns+conn+synack`.

Missing auditability:

- There is no structured artifact that explains why a `dns+conn+synack` assignment happened.
- The environment variable `PCAPTOOL_DEBUG_DNS_FALLBACK` can emit fallback debug lines, but this is not a normal run artifact.

## 14. Step-by-step examples

### Example A: direct DNS answer and later connection

Events:

1. Device queries `api.example.com`.
2. DNS response contains `api.example.com A 1.2.3.4`.
3. Device connects to `1.2.3.4:443`.

Expected matrix result:

- `DNSName = api.example.com`
- `DNSSource = dns+synack`

This is strong packet-time DNS evidence plus observed connectivity.

### Example B: query seen, response missing, later connection

Events:

1. Device queries `api.example.com`.
2. Response is missing or has no usable A answer.
3. Device connects to `1.2.3.4:443` within the hard-coded fallback window.
4. No other unresolved eligible DNS query competes in that window.

Possible matrix result:

- `DNSName = api.example.com`
- `DNSSource = dns+conn+synack`

This is inferred and risky because no DNS answer proved `api.example.com -> 1.2.3.4`.

### Example C: Cisco query followed by unrelated AWS/S3 connection

Events:

1. Device queries `www.cisco.com`.
2. DNS response is missing/truncated.
3. Device connects to an AWS/S3-looking public IP within the fallback window.
4. `www.cisco.com` is the only eligible unresolved query.

Possible current behavior:

- AWS/S3 IP can be labelled `www.cisco.com` with `dns+conn+synack`.

This is the serious false-positive pattern.

### Example D: unresolved endpoint has TLS certificate SAN

Events:

1. Matrix has unresolved public TCP row `54.164.104.91:5000`.
2. `--tls-cert-lookup` is enabled.
3. Probe order is row port first, then 443, then 8443.
4. Certificate SAN selects `api.example.com`.

Expected matrix result:

- If SAN came from `54.164.104.91:5000`: `tls-cert-san+matrix`.
- If SAN came only from fallback 443 or 8443: `tls-cert-san+matrix-fallback`.

This is active probe-time endpoint labeling, not capture-time DNS evidence.

### Example E: one issuer has strong evidence, another is mid-session

Events:

1. Issuer A has `8.8.8.8 tcp/443 api.example.com dns+synack`.
2. Issuer B has `8.8.8.8 tcp/443 <empty> mid-session`.
3. Donation runs after stronger attribution.

Expected result for issuer B:

- `DNSName = api.example.com`
- `DNSSource = donated+ipport`

If the donor was only `dns+conn+synack`, the donated source would be `donated+ipport+conn`.

## 15. Recommendations

1. Prevent false `dns+conn+synack` by stopping query-only fallback from inserting destination IPs into DNS transactions by default, or make it opt-in/audit-only.

2. Expose or reduce the query-only fallback window. The current hard-coded 5 second `maxConnDelay` is separate from `--topology-dns-window`, which is confusing operationally.

3. Strengthen uniqueness requirements before any inferred query-to-connection attribution:
   - exactly one eligible DNS query;
   - exactly one candidate destination tuple;
   - no repeated attachment of one query to many IPs;
   - optional CSV/PTR/TLS contradictions considered as blockers.

4. Rename or split `dns+conn+synack` to clarify that it is inferred, for example `dns-query+conn-inferred`.

5. Do not allow `dns+conn+synack` to donate across peers unless the operator explicitly accepts that low-confidence propagation risk.

6. Add `dns-connection-correlation-audit.csv` with:
   - issuer;
   - DNS query name;
   - query timestamp;
   - response status;
   - destination IP/port/protocol;
   - connection timestamp;
   - delta;
   - match mode;
   - candidate counts;
   - CSV guard result;
   - selected/rejected decision;
   - final evidence/source.

7. Treat source labels as confidence tiers:
   - high: direct DNS/SNI with exact endpoint connection;
   - medium: CSV, active exact matrix completion, TLS exact-port, FCrDNS PTR;
   - low: raw PTR, TLS fallback, query-only inferred connection, inferred donation.

8. Add regression tests for:
   - Cisco/AWS query-only false attribution;
   - one query followed by multiple SYNs;
   - multiple unresolved queries in the fallback window;
   - missing SYN-ACK but `dns+conn+synack` label;
   - cross-file DNS query/response mismatch;
   - CNAME-only responses;
   - AAAA-only responses;
   - DNS TC bit behavior;
   - SNI evidence source propagation;
   - `--disable-sni` excluding TCP DNS;
   - inferred donor propagation risk.

