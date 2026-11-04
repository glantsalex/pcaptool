# Invocation and input diagnostics

Pcaptool emits newline-delimited JSON diagnostics to stderr at INFO severity.
These are independent of `--no-banner` and `PCAPTOOL_NO_PROGRESS`.

- `invocation`: original argv (including argv[0]) and working directory.
- `effective_options`: dnsextract settings after YAML/default/CLI resolution.
- `input_access`: supplied/effective path and absolute resolved path. `readable`
  means the path could be opened with the expected file/directory type, not that
  its contents were validated. Missing optional DNS overlays are `optional_absent`.
- `input_load`: `loaded` only after the existing loader succeeds; failures are
  `load_failed`. The DNS CSV load also includes the optional topology overlay.
- `capture_discovery`: resolved capture directory and number of discovered files.
  Discovery does not claim that every capture packet has been parsed successfully.

Inputs include application YAML, fleet, DNS CSV and its adjacent topology overlay,
normalization rules, and cumulative direction registry. A registry without a fleet
is identified as unused. Registry merge/render commands also report their input
files.

Paths containing spaces or newlines remain unambiguous through JSON quoting.
Environment variables and file contents are not logged. Shell `--post-hook` bodies
are redacted in argv and effective options because they may contain credentials;
this never modifies execution arguments. Output paths appear in effective options,
but are not reported as existing inputs.

Access checks add one open/stat/close per configured input, with no extra PCAP
content pass. They are diagnostic only: existing validation and failure policy
remain unchanged. Normal extraction stages can load some inputs later in the run,
so an early readable record is separate from a later successful-load record.
