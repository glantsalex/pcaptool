# Opt-in memory diagnostics

## Purpose and scope

Investigate memory growth in `dnsextract`, particularly the interval reported as
“Writing fleet trail artifacts”. This instrumentation is not a memory fix.
It preserves packet admission, inference, ordering, deduplication, counters and
artifact contents. PTI and its cloud deployment are unchanged.

Implementation: `internal/diagnostics/memory.go`, `cmd/dnsextract.go` and
`cmd/syntrail_artifacts.go`. Regression coverage is in
`internal/diagnostics/memory_test.go` and `cmd/dnsextract_diagnostics_test.go`.

Set `PCAPTOOL_DIAGNOSTICS_DIR` to a writable local directory to enable it. Unset or
empty means disabled: no sampler, memory reads, profiles or diagnostic directory.
The environment switch works with CLI arguments and YAML configuration. It is
independent of `--debug` and `--disable-sni`. It applies to `dnsextract`, not the
standalone direction-registry commands. Each invocation creates a unique child
directory; stderr prints its path. Files are mode 0600; the new child is 0700.

## Evidence collected

- `memory.jsonl`: metadata (PID, Go build information, GOMAXPROCS), checkpoints,
  and memory samples every two seconds. Timestamps are UTC; elapsed values use
  the monotonic run clock, in milliseconds.
- Go heap allocated/in-use/idle/released bytes, cumulative allocated bytes, live
  heap objects, Go runtime system bytes, GC count/pause totals and goroutine count.
- On Linux, process `VmRSS`, `VmHWM` and `VmSwap`, in KiB. These are process-wide,
  not host-wide. On other systems an unavailable `/proc/self/status` is recorded
  explicitly; Go memory data remains available.
- DNS transaction and edge counts; fleet record slice lengths/capacities, classified
  bucket lengths/capacities and per-writer input counts. Counts come from the owning
  pipeline goroutine. The background sampler never reads pipeline maps or slices.
- `heap-NNN.pprof`: sampled allocation stacks at named checkpoints. The matching
  JSON checkpoint names the profile. It is written before the profile, so a kill
  during profiling can leave a missing/incomplete profile next to a valid marker.

The checkpoints bracket DNS scanning, connection scanning, fleet accumulator
transfer or sidecar scan, classification, private selection, each fleet artifact
selection/writer, direction SQL and the remaining topology/manifest output.
`previous_stage_ms` measures time since the preceding checkpoint, including any
profiling overhead. The last periodic sample identifies the active stage. Neither
an end checkpoint nor shutdown cleanup is possible after SIGKILL/OOM.

No IP addresses, packet payloads, credentials or configuration contents are added
to diagnostic records. Profiles contain allocation stacks, not a raw heap dump.
The normal invocation logs still contain input paths as documented separately.

## Build and validate

From the pcaptool repository, with its Go toolchain/dependencies available:

```bash
go test ./...
go test -race ./internal/diagnostics ./cmd \
  -run 'Test(SamplesProfilesAndLifecycle|WriteErrorsAreReported|DNSExtractDiagnosticsPreserveArtifacts)$' \
  -count=1
go build ./...
go build -o bin/pcaptool-diagnostic .
```

This leaves `./pcaptool` intact. Use the diagnostic binary explicitly; the existing
`run-dnsextract-*.sh` scripts currently select `./pcaptool` themselves and setting
only the diagnostic environment variable will not change which binary they use.

## Controlled local run for 401240-1

Start with one capture, then run the full day separately. Use a fresh workspace
for each run. The following reproduces the local 401240 script's relevant flags,
with a private copy of DNS inputs because extraction can update the DNS CSV.
It does not claim to reproduce every cloud argument or cumulative registry state.

```bash
cd /home/alex/go/src/github.com/aglants/pcaptool
run_dir=$(mktemp -d /tmp/pcaptool-memory-investigation-401240-XXXXXX)
mkdir -p "$run_dir/config"
cp data/dns-ip.csv "$run_dir/config/dns-ip.csv"
if [ -f data/topology-401240-1.csv ]; then
  cp data/topology-401240-1.csv "$run_dir/config/"
fi

PCAPTOOL_DIAGNOSTICS_DIR="$run_dir/diagnostics" \
  /usr/bin/time -v -o "$run_dir/time.txt" \
  ./bin/pcaptool-diagnostic dnsextract \
    -r "$HOME/pcap-data/401240/401240-1/input/2026/11/01" \
    --net-id 401240-1 \
    --output-root "$run_dir/artifacts" \
    --fleet "$PWD/data/fleet-401240-1.txt" \
    --dns-ip-file "$run_dir/config/dns-ip.csv" \
    --dns-normalization-rules "$PWD/data/pcaptool.rules.yaml" \
    --exclude-ports 53,123 \
    --enforce-private-as-source \
    --ftp-control-ports 21 \
    --ftp-passive-min-port 10000 \
    --allow-private-dns-donation \
    --disable-sni \
    > "$run_dir/run.log" 2>&1
printf 'Evidence: %s\n' "$run_dir"
```

For the one-file smoke check, replace `-r` with a temporary directory containing a
copy of one input capture. Keep source PCAPs and fleet files unchanged. The existing
`monitor-pcaptool.py` matches the process name `pcaptool` and will not automatically
attach to `pcaptool-diagnostic`; it is not required for the built-in sampler.
`time.txt` records aggregate CPU/elapsed time and peak RSS, not interval CPU.
Interval CPU monitoring would require a monitor that accepts the diagnostic PID.

For the comparison stream use 301686-1, its fleet, the 2026/10/10 input directory,
and its logical-services file if matching the existing local script. Copy its
optional topology overlay too. Run streams sequentially with the same diagnostic
binary and consistent settings; keep hashes of binary, configs and fleet inputs.
Do not compare the old local binary with the new binary as if instrumentation were
the only difference: the pre-investigation local executable predates the deployed
revision. A full-day investigation needs both streams' profiles and metadata.

The latest reported cloud failure is stream 401240-1, input day 2026-11-02,
job `pulse-topology-3ef32f64-6d75-4c5f-9e16-a82996693ed5` in pulse-wl. November 1
is the available local baseline; a successful November 1 run does not settle the
November 2 failure. Match that day's PCAPs, fleet, effective flags, cumulative
registry, image revision and concurrency before calling a local run a cloud replay.

## Reading the results

Choose the diagnostic child directory printed in `run.log`. Find a checkpoint
in `memory.jsonl`, then use its `heap_profile` filename:

```bash
go tool pprof -top -inuse_space ./bin/pcaptool-diagnostic /path/to/heap-NNN.pprof
go tool pprof -top -alloc_space ./bin/pcaptool-diagnostic /path/to/heap-NNN.pprof
```

`inuse_space` estimates retained Go allocations; `alloc_space` is cumulative
allocation traffic and can expose large temporary copies. Compare profiles from
before and after fleet classification/selection/writing. RSS and Go heap values
measure different things, so consult both. Slice capacity is slots, not bytes.
The small final JSON size or fleet size alone does not measure retained raw
observations.

## Limitations and failure policy

No forced GC, CPU profiler, HTTP endpoint, changed heap sample rate, or per-packet
logging is introduced. Heap profiles use Go's normal sampling and GC accounting;
they can lag current liveness by GC cycles. Profiling and `ReadMemStats` have
runtime overhead and can affect timing/peak memory. The interval sampler pauses
while a heap checkpoint holds the recorder lock; short spikes may be missed.
This is diagnostic evidence, not an uninstrumented performance benchmark.

Diagnostic files are written directly without application-level buffering, but
are not fsynced on every sample. A disk/full permission error is returned at
shutdown; remaining pipeline work may complete before that error is reported.
Failure to initialize diagnostics aborts before processing starts. Diagnostics
never silently turns itself off after an I/O failure. A missing final marker can
also mean external interruption; it alone is not proof of OOM.

The diagnostic directory is separate from the artifact manifest and is not
uploaded by PTI. Collect local evidence before considering any cloud wiring.
Unsetting `PCAPTOOL_DIAGNOSTICS_DIR` disables instrumentation. No cloud rollout or
memory optimization is part of this change.

## Implementation validation — 2026-11-09

Branch: `diagnostics/fleet-artifact-memory`; verification baseline HEAD:
`2f07666560c86d19561ad9f1a2e3994f6debb291`. Implementation remains uncommitted.

- `go test ./...`: passed across all packages (before final shutdown hardening).
- Final targeted regression/race check: passed:

  ```bash
  go test -race ./internal/diagnostics ./cmd \
    -run 'Test(DisabledAndInvalidDestination|SamplesProfilesAndLifecycle|WriteErrorsAreReported|ParseLinuxStatus|ProfileCreationFailure|DNSExtractDiagnostics.*)$' \
    -count=1
  ```

- Final `go build ./...` and `go build -o bin/pcaptool-diagnostic .`: passed.
- Artifact equivalence tests cover shared/separate scans and debug off/on; all
  output bytes match with diagnostics enabled/disabled, excluding the manifest's
  run-specific metadata.
- Final real-capture smoke: exit 0 using a copy of
  `401240-1_20261101000015-a01.pcap` (19,334,016 bytes), the existing fleet and copied
  DNS inputs. Evidence directory:
  `/tmp/pcaptool-diagnostics-smoke-final-20261109`. It contains the exact invocation
  in `command.json`, run/time logs, artifacts, 19 checkpoints, 13 readable heap
  profiles, and `inuse_space`/`alloc_space` text reports. No full day was executed.
- The default `/usr/local/go` installation lacks `go tool pprof`. Profiles were
  successfully validated with the existing cached tool:
  `/home/alex/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.24.11.linux-amd64/pkg/tool/linux_amd64/pprof`.
  Invoke that executable directly with the same arguments if needed here.
- Built diagnostic executable SHA256:
  `d67358fd64b987fd06bd8155ca2e20e9c9eed7e5ee309292f8651fd0ef89cb9c`.
  The original `./pcaptool` hash and pre-existing tracked edits were verified
  unchanged. Local scripts/configs, including the untracked monitor, were preserved.

Review: no output-semantic or packet-hot-path changes were introduced. Sampling
uses only runtime/process metadata on its background goroutine; pipeline counters
are captured synchronously. Shutdown joins the sampler and reports I/O errors.
Profiles affect timing and memory, so the remaining task is controlled full-day
comparison, followed by allocation analysis; the root cause is not yet established
by this instrumentation smoke check. Nothing has been committed, pushed or
cloud-deployed as part of this change.

## Fleet allocation fix (2026-11-09)

The follow-up fix remains on `diagnostics/fleet-artifact-memory`. It changes fleet
storage allocation and selection, not packet admission, DNS retention, fleet
inference, artifact schemas, registry semantics, SQL or PTI deployment settings.

- `internal/syntrail/csv.go`: public-server deduplication grows its map by actual
  distinct tuples and allocates the sorted result once the distinct count is known.
  It preserves protocol normalization and the complete tuple sort order.
- `internal/syntrail/split.go`: a one-partition selector makes only the requested
  independent public/private buffer; the existing two-partition API is unchanged.
- `cmd/syntrail_artifacts.go`: only those explicitly owned selections are compacted
  by the FTP and UDP summary filters. FTP control evidence is collected in full
  before compaction, so late control packets still suppress earlier passive data.
  Rejected tails are cleared; borrowed-input wrappers retain their old contract.
  TCP-only selections allocate for matching records instead of all candidates.
- `internal/syntrail/classify.go`: count then fill exact-size bucket buffers, with
  unchanged classification and within-bucket order.
- `internal/syntrail/scan.go`: final TCP/UDP assembly reuses existing capacity or
  allocates the required combined capacity exactly once. TCP duplicates, UDP
  ordering/earliest evidence and transfer-of-ownership semantics are unchanged.

No forced GC or altered concurrency is used to obtain the allocation savings.
The first patch intentionally leaves DNS and raw evidence retention unchanged.

Build separately to preserve both the old executable and diagnostic baseline:

```bash
go build -o bin/pcaptool-memory-optimized .
go test ./...
go test -race ./internal/syntrail ./cmd
go test ./internal/syntrail ./cmd -run '^$' \
  -bench 'Benchmark(ServerSummary|LocalitySelection|SummaryFilters|Classification|AccumulatorFinalization)Allocation' \
  -benchmem -benchtime=200ms -count=1
```

`cmd/syntrail_allocation_test.go` and
`internal/syntrail/allocation_regression_test.go` cover independent expected output,
late control evidence, compaction ownership/tail clearing, exact capacities,
classification rejection/ordering, accumulator expansion, and randomized tuple
ordering equivalence against a frozen baseline. Existing frozen artifact, scan
ordering, shared-versus-sidecar and debug-mode checks remain in use.

The allocation benchmark comparisons use the same synthetic inputs. In the
100,000-record duplicate-heavy summary case (16 unique tuples), allocation falls
from about 13.2 MB to 4.2 KB. Classification falls from about 54.0 MB to 10.4 MB;
summary filtering including the owned input buffer falls from about 31.2 MB to
10.4 MB. Selecting a 1% private partition falls from 10.4 MB to 0.11 MB.
These are allocated bytes per operation, not peak RSS estimates.

There is an explicit high-cardinality tradeoff: when all 100,000 input tuples are
unique, map growth allocates about 21.6 MB versus 13.2 MB in the old pre-sized
implementation, and unordered map enumeration requires more sorting work. This
case is covered by the benchmark; the improvement targets the measured highly
duplicated summaries. Runtime timings collected alongside a full PCAP run are
indicative only. Broad claims of speed improvement are not justified.

Full-day validation uses `/tmp/pcaptool-memory-fix-20261109/`. The preserved
`pcaptool-baseline` binary and SHA256-hashed initial config/fleet files are held
there. Every run receives a separate initial DNS input copy. PCAP paths, sizes and
mtime values are recorded; the full 240 GiB corpus was not rehashed. Validation
must compare every artifact byte, normalized manifest metadata (only run paths,
run ID and wall-clock start time differ), and final DNS/config contents. The
baseline and optimized run roots must not be shared.

The fresh local comparisons use `GOMAXPROCS=20`, followed by an optimized
`GOMAXPROCS=32` check because scanner concurrency follows that setting. This is
still local evidence; testing on the actual 32 GiB Batch VM with the failed
November 2 input is a separate rollout gate. Do not assume that a lower local
peak, or a successful 64 GiB-host run, proves cloud headroom.

### Full-day validation without a memory budget

The five fresh local runs completed with exit status 0. Config and fleet inputs
were frozen before running; each run used its own DNS CSV copy. For every completed
optimized run, all 15 artifact files matched the corresponding baseline (14 files
byte-for-byte and the manifest after normalizing only run-specific metadata).
Final configuration/DNS contents matched too. The preserved baseline 401240 output
also matched the previously supplied investigation output.

| Stream / settings | Baseline peak RSS | Optimized peak RSS | Baseline elapsed | Optimized elapsed |
| --- | ---: | ---: | ---: | ---: |
| 401240-1, GOMAXPROCS=20, diagnostics on | 40.03 GiB | 39.32 GiB | 235.53 s | 236.64 s |
| 301686-1, GOMAXPROCS=20, diagnostics on | 9.42 GiB | 8.07 GiB | 436.80 s | 443.89 s |
| 401240-1, GOMAXPROCS=32, diagnostics off | not measured with these settings | 32.77 GiB | — | 239.77 s |

The 32-worker run started before an RSS guard was added to the validation driver,
so that guard was not active for this execution. It finished normally, without
cancellation or OOM. Do not describe it as a guarded/terminated test. Its result
still fails the 32 GiB deployment criterion. The concurrency and profiling settings
both differ from the 20-worker run; their separate effects cannot be inferred from
this one comparison.

**Without an explicit memory budget, the allocation refactor alone did not
provide sufficient RSS headroom on a 32 GiB VM.** The later budgeted local tests
are recorded below. Cloud validation remains pending; this is not yet a proven
resolution of the cloud failure.

For 401240-1 at 20 workers, cumulative Go allocation decreased from about 565.08 GiB
to 532.00 GiB. The optimized process nevertheless had about 30.97 GiB RSS before
fleet artifact preparation. At classification completion, about 12.94 GiB of Go
heap was idle and almost none of it had been returned to the OS. GC counts did not
advance between connection completion and classification completion. Reducing
allocation can change GC timing without proportionately lowering peak RSS.
Profiles are sampled/GC-delayed; these observations are not a claim of a leak.

The next investigation step was an explicitly configured memory budget,
recorded below. Further redesign of retained scanning evidence remains an option
if that budget is insufficient in cloud validation. A possible next approach is summary accumulation during
non-debug scans, preserving exact device sets, late FTP control evidence, syslog
qualification and debug-trail contracts. This larger change was not implemented
silently as part of the allocation patch. DNS retention was not changed either.

Validation evidence and exact invocations are in
`/tmp/pcaptool-memory-fix-20261109/`:

- `all-tests.log`: `go test ./...` passed.
- `race-tests.log`: `go test -race ./internal/syntrail ./cmd` passed.
- `stage1-new-tests.log`, `final-focused-tests.log`: focused checks passed. The
  subsequently added randomized summary equivalence test passed separately with
  `go test ./internal/syntrail -run 'TestServerSummary' -count=1`.
- `final-bench.log`: allocation comparisons and the high-cardinality tradeoff.
- `comparison.json`: full artifact/config comparisons and measured RSS/runtime.
- Per-run `command.json`, `run.log`, `time.txt`, `result.json` and diagnostic
  profiles where enabled.
- `input-hashes.json` and per-stream capture manifests. Capture paths, sizes and
  modification times were checked again after validation; full PCAP content
  hashes were not computed.

`go build ./...` passed. The separate optimized binary is
`bin/pcaptool-memory-optimized`, SHA256
`b96b9ffd81d655257f09f91b637798e91b1927b96744e306444b968e6c1125be`.
The original `pcaptool` and `bin/pcaptool-diagnostic` executables and unrelated local
changes remain untouched. Changes are uncommitted and unpushed; PTI is unchanged.


### Budgeted local validation — 2026-11-09

Follow-up invocations used the same optimized binary with `GOMEMLIMIT=24GiB`
and `GOMAXPROCS=32`, SNI disabled, and separate output/config directories.
The diagnostic metadata records GOMAXPROCS but not the effective GOMEMLIMIT;
the latter is established by the supplied invocation, not the diagnostic log.

| Stream / input date | Diagnostics | Peak RSS | Elapsed | Exit |
| --- | --- | ---: | ---: | ---: |
| 301686-1 / 2026-10-10 | enabled | 9.28 GiB | 7m 02.17s | 0 |
| 401240-1 / 2026-11-02 | enabled | 23.55 GiB | 3m 48.72s | 0 |
| 401240-1 / 2026-11-02 | disabled | 24.00 GiB | 3m 55.70s | 0 |

Evidence directories:

- `/tmp/pcaptool-memory-budget-301686-i23kY4`
- `/tmp/pcaptool-memory-budget-401240-tCIqRs`
- `/tmp/pcaptool-memory-budget-401240-nodiag-2LB2iu`

The budgeted 301686 artifacts match its preserved same-day baseline. The two
November 2 runs for 401240 match all 14 ordinary artifacts byte-for-byte, the
manifest after normalizing run-specific paths/IDs/start time, and the final DNS
CSV. The uninstrumented run created no diagnostics directory.
The preserved unoptimized 401240 baseline is November 1: there is no same-day
unoptimized November 2 comparison. Cross-day memory numbers must not be presented
as a controlled measurement of the budget's effect alone.

`GOMEMLIMIT` is a soft per-Go-process runtime memory budget, not an RSS cap or a
shared container limit. It cannot reclaim live evidence and excludes memory
managed outside Go. Setting it in the Batch environment also affects PTI, whose
pcaptool subprocess inherits the environment; each process has its own budget.
See the [Go GC guide](https://go.dev/doc/gc-guide#Memory_limit).

Local budgeted validation passed. The next gate is one monitored Batch run for
401240-1 / 2026-11-02 on the existing VM, using a candidate image containing the
verified optimization and explicit memory/concurrency settings. Verify the image
revision, effective settings, artifact completion, and whole-VM memory headroom.
No candidate cloud run or deployment has been performed at this checkpoint.
The deployment renderer does not currently forward GOMEMLIMIT/GOMAXPROCS from
env files; an isolated job must set them explicitly in its environment.
