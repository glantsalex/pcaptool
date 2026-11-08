# Mapping observed endpoints to logical services

The purpose of a **logical services map (LSM)** is to show which services each
device communicates with, while remaining stable when destination IP addresses
or individual hostnames change.

For this first iteration, use a **flat, coarse-grained model**: keep the number of
logical services small, while preserving enough detail to inspect what was
actually observed.

## 1. Start from observed traffic

Use the network topology matrix (NTM) as the evidence source. Identify:

- The issuer/device.
- Destination DNS name and IP address.
- Protocol and destination port.
- Observation time and any available attribution or normalization information.

Distinguish observations from interpretation. A hostname may suggest a platform,
but it does not necessarily prove ownership. Leave unidentified traffic
unclassified instead of assigning it by guesswork.

An NTM issuer address is an observed identifier; it does not establish a stable
physical-device identity across captures.

## 2. Group by platform rather than individual component

Combine related endpoints into one service when that produces a useful,
understandable device dependency.

| Observed family | Logical service |
|---|---|
| GridX API, edge, metrics, and related storage | XENON platform |
| Microsoft updates, identity, Edge, and telemetry | Microsoft platform |
| Samsung account, cloud, and device services | Samsung platform |
| TeamViewer router hosts | TeamViewer |

Avoid separate services for every hostname, region, component, or deployment
environment unless that distinction is necessary for the current use case.

This grouping is a topology decision. It does not imply that the grouped
endpoints are interchangeable, nor is it an access-control policy.

## 3. Give each service a stable identity

A service has two essential attributes:

```yaml
id: microsoft_platform
name: Microsoft platform
```

Use a concise, stable, lowercase `snake_case` ID. Avoid embedding an IP address,
account number, instance identifier, or `_endpoint`/`_endpoints` suffix when the
service represents a broader platform.

Keep the display name readable. Rename IDs deliberately and update all
references consistently.

## 4. Choose the broadest useful DNS match with a defensible boundary

| Selector | Use it for | Example |
|---|---|---|
| `dns_suffix` | A domain or namespace belonging to the intended grouping | `evcharging.abb.com` |
| `dns_exact` | A specific exception, shared-cloud tenant, or ambiguous host | A particular Azure instance |
| `dns_regex` | A structured hostname family that suffix matching cannot isolate | GridX-prefixed S3 bucket names |
| `dns_contains` | An explicitly accepted broad naming heuristic | `teltonika` |

Prefer suffix matching where appropriate. It handles hostname churn without
enumerating every observed name.

A suffix includes the base domain and its subdomains, respecting DNS-label
boundaries. For example, `advam.com` matches `tms.advam.com`, but not
`notadvam.com` or `advam.com.example.org`.

Do not generalize a tenant-specific endpoint to an entire shared-cloud domain
such as `amazonaws.com`, `azure-devices.net`, or `cloudapp.azure.com`.

## 5. Make regexes structural and bounded

When several hostname components must all be present, use a regex that specifies
their positions and boundaries.

```yaml
dns_regex:
  - '^gridx-de-ds-[a-z0-9-]+\.s3\.[a-z0-9-]+\.amazonaws\.com$'
```

This requires the bucket prefix, the `s3` label, a region label, and the expected
domain ending.

Escape literal dots and anchor the expression. Test plausible future names as
well as misleading names with extra prefixes or appended domains. Document the
hostname forms the expression intentionally excludes.

A naming pattern remains a grouping heuristic, not proof of ownership.

## 6. Define rule semantics explicitly

The rule semantics are:

```text
(any DNS/IP alternative matches)
AND
(any listed protocol/port combination matches)
```

Endpoint alternatives may combine `dns_exact`, `dns_suffix`, `dns_contains`,
`dns_regex`, and `dst_ip_cidrs` with **OR** semantics:

```yaml
- id: xenon_platform_endpoints
  priority: 100
  service_id: xenon_platform
  match:
    dns_suffix:
      - gridx.ai
      - gridx.de
    dns_regex:
      - '^gridx-de-ds-[a-z0-9-]+\.s3\.[a-z0-9-]+\.amazonaws\.com$'
    transports:
      - proto: tcp
        ports: [443]
```

Two `dns_contains` values mean **either substring**, not “both substrings must
occur.”

Matching multiple alternatives within one rule should still produce one rule
match.

These match blocks use the native runtime schema. Put them in a combined
definitions file with `schema_version: 1`, `services`, and `rules`.

## 7. Keep protocol and port combinations bound together

Represent TCP and UDP separately:

```yaml
transports:
  - proto: tcp
    ports: [80, 443]
  - proto: udp
    ports: [443]
```

This allows TCP/80, TCP/443, and UDP/443. It does **not** introduce UDP/80.

Use observed protocol/port combinations as the starting policy. Do not add ports
merely because they are commonly associated with a vendor.

## 8. Consolidate rules deliberately

Prefer one rule per logical service when its DNS alternatives can share a
transport policy.

However, merging rules can broaden matching. If one hostname previously matched
TCP/80 and another TCP/443, a merged rule with both ports permits either hostname
on either port.

For the coarse iteration, this generalization was accepted where useful. Keep
separate rules when hostname-specific transport restrictions matter.

Distinguish these two objectives:

- Fewer **services** simplify the topology.
- Fewer **rules** simplify maintenance.

Multiple rules can still map to one service without adding topology nodes.

## 9. Separate matching scope from observed membership

A broad rule describes what *could* be classified into a service. The device map
describes what a particular device *actually communicated with*.

Never populate a device's service details with all globally known members of
that platform.

For example, a Microsoft rule may permit several namespaces and transports, but
a device's map must contain only its observed Microsoft communications.

## 10. Preserve uncertainty and handle conflicts explicitly

Keep unmatched observations identifiable during analysis. Do not infer a service
from an unattributed IP merely because another observation associated that IP
with a hostname.

Review overlapping rules. Remove redundant alternatives or resolve competing
classifications deliberately. In the classifier used for this exercise, lower
numeric priority wins, and competing matches at the winning priority are errors,
including matches mapping to the same service.

Preserve attribution and normalization evidence in the source or detailed review
artifacts. A simplified delivery artifact may omit that evidence, but
simplification must not be mistaken for increased certainty.

## 11. Validate against both the capture and synthetic cases

Before accepting a revision:

- Validate service references, unique IDs, selector syntax, and transport values.
- Reclassify the complete capture.
- Compare coverage and device/service assignments with the previous revision.
- Explain intentional changes, including service-ID migrations.
- Test suffix boundaries, regex near-misses, future hostnames, and shared-cloud
  exclusions.
- Test allowed and disallowed protocol/port pairs.
- Check DNS case/trailing-dot normalization and IP-churn invariance.
- Verify that missing DNS does not acquire an invented identity.
- Confirm that output transformations preserve the intended observations and
  duplicate counts.

Unchanged coverage alone is insufficient: assignments could change while the
total classified count stays the same.

## 12. Produce different views from the same logical result

| Artifact | Purpose |
|---|---|
| Full map | Human inspection of services and observed communications |
| Dictionary-encoded compact map | M2M exchange without repeatedly storing strings |
| Short map | `issuer_id` plus unique observed `svc_id`, `svc_name`, `proto`, and `port` combinations |

The compact map uses deterministic, zero-based, file-local dictionary indices:

- Arrays of strings for IP addresses, DNS names, and rule IDs.
- An array of `{id, name}` objects for services, keeping the pair together.
- A shared IP dictionary for issuer and destination addresses.
- References for normalization DNS names and rule IDs as well.
- `0` is a valid index; missing endpoint values use `null`. Absent fields remain
  absent.
- Validate reference types and bounds. Indices are not stable identities across
  different files.

Decoding the compact map must reproduce the full map exactly. Generate both
representations from the same full model.

The short map deliberately removes endpoints and provenance. Its protocol/port
entries come from actual device observations, not the full set permitted by the
rules. Issuers without classified services retain empty service lists.

Times use UTC. In the delivery maps from this exercise, timestamps retain `Z` and
exactly three fractional-second digits; finer precision is truncated. This loss
of precision is explicit, and observations are not deduplicated as a side effect.

Version artifacts, record the capture date in filenames, preserve earlier
revisions, and document schema changes or intentional information loss.

## Implementation status

The native runtime implements mixed DNS selectors and explicit `transports`.
Enable it with `dnsextract --logical-services <definitions.yaml>` or the
`dnsextract.logical_services` configuration key. It generates full, compact,
and short maps from finalized NTM as the last analysis stage before the manifest
and post-hooks.

Only public destination addresses enter LSM, including eligible IPv6 addresses.
Private, CGNAT, loopback, link-local, documentation, multicast, and reserved
destinations are excluded; NTM is unchanged. Issuers with public but unmatched
observations remain visible with empty service lists.

Runtime definitions contain only `schema_version: 1`, `services`, and `rules`.
For earlier exercise definitions, remove draft metadata such as `artifact_type`,
`draft_revision`, `stream_id`, and `capture_date`, then add `schema_version: 1`.
Rules require `match.transports` with explicit protocol/port combinations;
unsupported fields such as `any_port` are rejected.
The combined example is in
[`configs/logical-services-definitions.example.yaml`](../configs/logical-services-definitions.example.yaml).
See [runtime details](../docs/architecture/lsm-implementation.md) for output
contracts, validation, and failure behavior.
