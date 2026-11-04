# Flow-direction SQL generation

`cmd/flow_direction_sql.go` is the shared renderer for daily artifacts and
`render-flow-direction-sql` cumulative-registry output. The CLI contract lives in
`cmd/direction_registry.go`; daily callers live in `cmd/syntrail_artifacts.go`.
Evidence learning and persistence remain in `internal/direction`, unchanged by
this refactor. No stream-specific addresses or rule counts are built into code.

## Rule representation and ordering

Each eligible endpoint contributes a canonical reversal rule with independent
IP-side and port-side selectors, protocol, IP and port. Servers use source IP and
source port. Probes use **destination IP and source port**; the port belongs to
the fleet target, not the probe. Forward/conflict conditions are mechanical
mirrors of both selectors. They are not a second manually maintained rule list.

Grouping keys include protocol, IP selector, IP value and port selector. Ports
are deduplicated and sorted numerically within each group. Groups are sorted by
protocol, IP side (source before destination), literal IP string, then port side.
Mirrored groups retain the canonical order. This ordering does not assign rule
priority: OR alternatives share one reversal reason. The old renderer used
input order; canonical sorting makes equivalent unordered input deterministic.
Stored registry order and merge behavior have not changed.

## Preserved decisions

1. Outside-recognized-range source to private/shared destination reverses.
2. Private/shared UDP source port 53 with destination port not 53 reverses.
3. With learned UDP rules, private/shared UDP involving port 53 is then preserved.
4. Per protocol, a learned reversal match reverses only when the mirrored forward
   match is false. TRUE/TRUE conflicts and TRUE/NULL uncertainty preserve the row.
5. Everything else retains orientation.

TCP and positively qualified syslog UDP are supported. The DNS preservation
branch is redundant for TCP-only or empty collections and omitted there. It is
**not redundant with learned UDP**: for example, a syslog server's UDP/6514 to
port 53 must still be preserved. Protocol checks are factored into decisions,
with independent learned flags for TCP and UDP. No COALESCE is applied to learned
flags. SQL three-valued logic is retained through grouping and mirroring.

The query retains the RFC1918 and 100.64/10 IPv4 prefixes, safe IP parsing,
COALESCE-to-false classification, and lowercase protocol. Invalid/null IPs and
IPv6 are outside the recognized ranges, just as before. This can cause a swap
when their destination is recognized private; changing that policy is separate
work. This refactor does not change fleet membership, device attribution,
reason labels, counts, rule expiry, learning or registry schema.

The final 12-column projection retains column order, names, and source types;
IPs, ports, byte counters and packet counters exchange together. Device IDs and
timestamps are untouched. There are no joins, aggregation, DISTINCT, UDFs or
subqueries over rule arrays. Duplicate rows remain duplicate rows.

## SQL layout and consumer compatibility

`parsed`, `base`, `learned`, and `decide` use explicit projections. Parsed IPs are
named once for readability, not a guarantee of physical evaluation count or
reduced scans. Each CASE condition and THEN occupy separate lines. Alternatives
and grouped IN lists are wrapped at token boundaries, targeting 100 characters.
An indivisible identifier, string literal or placeholder may exceed that target.

The `direction-generator: cumulative-v1` marker and schema version are retained
because policies and persistence contracts are unchanged. A rendering comment
describes grouped scalar rules. The CREATE keyword and target now occupy separate
lines. Consumers must not require a single-line CREATE header or DNS predicate.
PTI's accompanying changes validate whitespace independently and submit/persist
the actual formatted SQL, including supported view options.

## Regression evidence

`cmd/testdata/flow_direction/404163-1.registry.json` is the real cumulative
2026-10-04 validation snapshot. Its frozen `.before.sql` was generated before
this refactor and verified byte-for-byte against the saved user artifact. It has
71 unique reversal predicates and 71 exact mirrors (28 server and 43 probe
predicates), grouped into 38 reversal groups. Those are fixture observations,
not generator limits. The neighboring `.sql` is the readable new golden output.

Empty, single-rule and mixed TCP/UDP fixtures have independent frozen baselines.
The mixed fixture includes long port lists, both roles, qualified UDP and DNS
collisions. Never regenerate `.before.sql` using the new generator.

`compare_sql.py` extracts scalar rules from the frozen SQL, independently evaluates
TRUE/FALSE/NULL decisions, and executes both old/new SELECTs in SQLite with IP/IF
adapters. It compares every output field, column order, reason, and duplicate
multiplicity using multisets. Cases cover every actual rule and its mirror,
conflicts, protocol case, null selectors, invalid/IPv6/range-boundary addresses,
DNS, unequal counters, and deterministic randomized rows. Go tests additionally
verify grouping, exact mirrors, input shuffling, unchanged registries, formatting,
and identical CLI/shared rendering.

Run `go test ./cmd ./internal/direction`, then `go build ./...` and `go test ./...`.
Python 3 (standard library only) is needed for the independent SQL comparisons.

## BigQuery validation and rollout

Local SQL emulation does not certify BigQuery expression types or MV eligibility.
Before deployment, use isolated, hourly start_time-partitioned source tables with
the real schema in an authorized test dataset. Create old/new views with the
same supported options and location; compare all fields and multiplicities over
a fixed input snapshot, including duplicate rows and NULLs. Check actual metadata
for partition alignment and MV mode, refresh behavior and permissions. Do not
replace a production view for this validation. No live BigQuery validation or
performance claim is made by these tests.

Release the compatible PTI and pcaptool changes together. Structural query text
changes can cause one replacement/refresh even with unchanged registry evidence.
Settle pending jobs before rollback; older PTI versions require the old one-line
CREATE header and may reject application state saved with the new layout.
