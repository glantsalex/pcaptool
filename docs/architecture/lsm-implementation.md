# Native logical services maps

## Scope and invariants

`internal/logicalservice` owns the flat catalog, strict rule validation, and
immutable classifier. `internal/lsm` projects finalized in-memory NTM into
public-only device/service maps. `cmd` loads definitions before capture work and
writes LSM after existing reports, before `_run-artifacts.json` and post-hooks.
No packet extraction, DNS attribution, or original NTM semantics change.

Enable with `--logical-services <path>` or `dnsextract.logical_services` in YAML.
Configuration-relative definitions paths resolve against the configuration
directory. Omitting the option leaves LSM disabled.

## Definitions contract

A single YAML document contains `schema_version: 1`, `services: [{id, name}]`,
and `rules`. This is the initial supported contract: rules require
`match.transports`. The separate catalog/rules package loaders use the same
rule syntax. Unsupported fields are rejected by strict validation.

Each rule requires `id`, `priority`, `service_id`, and `match`.
Matching is:

```
(any DNS/IP selector matches) AND (any explicit transport alternative matches)
```

DNS selectors (`dns_exact`, `dns_suffix`, `dns_contains`, `dns_regex`) can coexist.
Values within each selector are alternatives (OR). Suffixes match the domain
itself and subdomains at label boundaries. DNS matching is case-insensitive
through normalization; regexes must be anchored and use Go's regexp syntax.
`dns_contains: [a, b]` means either substring, not both. For an ordered compound
condition, use a regex. Explicit IPv4 `dst_ip_cidrs` are also supported; they are
alternatives to DNS selectors, not additional restrictions.

`transports: [{proto: tcp, ports: [80, 443]}, {proto: udp, ports: [443]}]`
allows TCP/80, TCP/443, UDP/443, never UDP/80. Each protocol appears once.
Ports are nonempty lists of unique integers 1–65535. There is no wildcard port.
All selector alternatives share the transport policy; use separate rules when
host families require distinct policies.

Lowest numeric priority wins. Multiple matching selectors in one rule count
once. Multiple rules tied at the winning priority are an error, including rules
with the same service ID. Unknown YAML fields, duplicate IDs, missing catalog
references, malformed selectors, and invalid transports fail validation.

## Output contract

Files live in the normal run directory. Prefix is
`<stream-id>-<capture-date YYYYMMDD>` (or `unknown` when no capture date exists).

| Suffix | Manifest key | Content |
|---|---|---|
| `logical-services.yaml` | `logical_services_definitions` | Validated definitions snapshot |
| `device-services.full.json` | `logical_services_full` | Human-readable map and observed endpoints |
| `device-services.compact.json` | `logical_services_compact` | Minified dictionary representation |
| `device-services.short.json` | `logical_services_short` | Only issuer and service/transport tuples |
| `logical-services-summary.json` | `logical_services_summary` | Observation, issuer, service, and edge counts |

The manifest also has a `logical_services` statistics object when enabled.
Counts describe observations and topology, not packet volumes, sessions,
device health, or proven successful application communication.

Full and compact maps use `map_schema_revision: 3`. Full devices have `issuer`,
`services` and `unclassified_endpoints`. Each service has `svc_id`, `svc_name`,
and `endpoints`. Endpoints carry `dst_ip`, `dns_name`, `proto`, `port`, `seen_at`,
`rule_id` (when matched), and optional normalization/CNAME evidence. NTM row
indices and DNS attribution source fields are intentionally omitted.

Unmatched public observations remain in `unclassified_endpoints` with
`no_dns_attribution` or `no_matching_rule`; no service is guessed.
Only issuers with eligible public observations are emitted. An issuer with
only unmatched public observations has an empty `services` list.

Compact dictionaries are sorted arrays of IPs, DNS names, rule IDs, and paired
service `{id,name}` objects. References are zero-based and local to each file;
they are not stable identifiers across runs. Missing DNS is JSON null, never
index zero. `CompactMap.Expand` validates references and restores the full map,
including observation multiplicity and optional evidence.

Short output is a top-level array:

```json
[{"issuer_id":"10.0.0.1","services":[{"svc_id":"team_viewer","svc_name":"TeamViewer","proto":"tcp","port":443}]}]
```

It contains unique observed service/protocol/port combinations, never the
unobserved combinations permitted by a rule.

## Public scope, determinism, and failures

Public destination filtering precedes classification. It excludes private,
CGNAT, loopback, link-local, multicast, documentation, and reserved ranges.
IPv4-mapped addresses follow IPv4 eligibility. IPv6 is restricted to eligible
global-unicast space. The explicit special-range policy is tested in
`internal/lsm`; maintain it deliberately as address allocations evolve.
This is address eligibility, not proof of Internet reachability.

Identical finalized NTM and definitions yield identical map content.
Rows are sorted deterministically; duplicates are preserved in full/compact
maps. UTC timestamps truncate to exactly three fractional digits. Issuer IPs
are capture identifiers, not durable physical-device identities.

Invalid input, classification conflicts, and cancellation fail generation.
All LSM files are staged before publication, and handled publication errors
remove files created by that call. Existing paths are not intentionally
overwritten. A process crash during the sequence of renames can leave a subset;
the final run manifest is the completion boundary. Existing NTM reports may
already exist after an LSM failure. Run-directory collision protection remains
unchanged: replay into a fresh run directory.

## Validation

Tests cover mixed-selector matching, protocol/port isolation, conflicts,
malformed/unsupported rules, public scope, timestamp precision, determinism, empty
maps, lossless dictionary round trips, cleanup on failure, CLI/config paths,
and capture-to-manifest integration with LSM enabled and disabled.

Native replay of stream `301686-1`, capture `2026-10-10`, matched the earlier
reviewed exercise: 168,077 input observations, 112,821 excluded, 55,256 public,
54,931 classified, 325 unmatched, 14,813 issuers, 67 services, 20,700 edges.
All classified service/rule assignments and all 36,722 short-map tuples matched.
Unmatched reason wording is generic in native output; observation data matches.

For manual rollout, use a reviewed combined definitions file, inspect the
summary and unmatched observations, and confirm the consuming UI understands
dictionary references and the short map's observed transport tuples.
