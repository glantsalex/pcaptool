package syntrail

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"

	pcaputil "github.com/aglants/pcaptool/internal/pcap"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// ScanProgressFunc receives file-level scan progress updates.
type ScanProgressFunc func(done, total int, file string)

// ScanOptions controls packet capture scanning behavior.
type ScanOptions struct {
	// FleetIdentity resolves the fleet-side IMSI before observations are aggregated.
	FleetIdentity func(Record) string
	// Workers is the maximum number of capture files scanned concurrently.
	// Values <= 1 preserve the historical sequential scan behavior.
	Workers int

	// Progress is called after each file scan completes. It is optional and is
	// invoked from the coordinating goroutine, not from worker goroutines.
	Progress ScanProgressFunc

	// PacketAdmission, when non-nil, is applied immediately after packet
	// decoding. Rejected packets cannot contribute trail evidence.
	PacketAdmission pcaputil.PacketAdmission
	SyslogCache     *SyslogCache
	// SyslogEligible restricts qualification to fleet -> private nonfleet.
	SyslogEligible func(src, dst netip.Addr) bool
}

// ScanFiles scans packet captures for raw observed IPv4 TCP SYN and eligible
// UDP trail evidence.
func ScanFiles(ctx context.Context, files []string) ([]Record, error) {
	return ScanFilesWithOptions(ctx, files, ScanOptions{Workers: 1})
}

// ScanFilesWithOptions scans packet captures for raw observed IPv4 TCP SYN and
// eligible UDP trail evidence using bounded concurrent file scanning.
func ScanFilesWithOptions(ctx context.Context, files []string, opts ScanOptions) ([]Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, nil
	}
	cache := opts.SyslogCache
	if cache == nil {
		cache = NewSyslogCache()
	}
	scanner := func(ctx context.Context, path string, admit pcaputil.PacketAdmission) ([]Record, error) {
		return ScanPacketBatch(ctx, path, ScanOptions{PacketAdmission: admit, SyslogCache: cache, SyslogEligible: opts.SyslogEligible, FleetIdentity: opts.FleetIdentity})
	}
	records, err := scanFilesConcurrentWithScanner(ctx, files, opts.Workers, opts.Progress, opts.PacketAdmission, scanner)
	ApplySyslogQualifications(records, cache)
	return records, err
}

func scanFilesSequential(
	ctx context.Context,
	files []string,
	progress ScanProgressFunc,
	admit pcaputil.PacketAdmission,
) ([]Record, error) {
	accumulator := NewAccumulator()
	for i, file := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fileRecords, err := ScanPacketBatch(ctx, file, ScanOptions{PacketAdmission: admit})
		if progress != nil {
			progress(i+1, len(files), file)
		}
		if err != nil {
			return nil, err
		}
		accumulator.Add(fileRecords)
	}
	return accumulator.TakeRecords(), nil
}

func scanFilesConcurrent(
	ctx context.Context,
	files []string,
	workers int,
	progress ScanProgressFunc,
	admit pcaputil.PacketAdmission,
) ([]Record, error) {
	return scanFilesConcurrentWithScanner(ctx, files, workers, progress, admit, func(ctx context.Context, path string, admit pcaputil.PacketAdmission) ([]Record, error) {
		return ScanPacketBatch(ctx, path, ScanOptions{PacketAdmission: admit})
	})
}

type scanFileFunc func(context.Context, string, pcaputil.PacketAdmission) ([]Record, error)

func scanFilesConcurrentWithScanner(
	ctx context.Context,
	files []string,
	workers int,
	progress ScanProgressFunc,
	admit pcaputil.PacketAdmission,
	scanner scanFileFunc,
) ([]Record, error) {
	if workers < 1 {
		workers = 1
	}
	if workers > len(files) {
		workers = len(files)
	}

	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs := make(chan scanFileJob)
	resultsCh := make(chan scanFileResult, workers)

	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			for job := range jobs {
				if err := scanCtx.Err(); err != nil {
					resultsCh <- scanFileResult{index: job.index, path: job.path, err: err}
					continue
				}

				records, err := scanner(scanCtx, job.path, admit)
				if err != nil {
					cancel()
				}
				resultsCh <- scanFileResult{
					index:   job.index,
					path:    job.path,
					records: records,
					err:     err,
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	accumulator := NewAccumulator()
	pending := make(map[int]scanFileResult, workers)
	nextDispatch := 0
	nextCommit := 0
	jobsClosed := false
	var firstErr error
	done := 0
	ctxDone := scanCtx.Done()
	for resultsCh != nil {
		if !jobsClosed && (firstErr != nil || nextDispatch == len(files)) {
			close(jobs)
			jobsClosed = true
		}

		var dispatchCh chan<- scanFileJob
		var nextJob scanFileJob
		// Bound the uncommitted file-index frontier. This prevents a slow early
		// capture from allowing every later file batch to accumulate in memory.
		if !jobsClosed && scanCtx.Err() == nil && nextDispatch-nextCommit < workers {
			dispatchCh = jobs
			nextJob = scanFileJob{index: nextDispatch, path: files[nextDispatch]}
		}

		select {
		case dispatchCh <- nextJob:
			nextDispatch++

		case result, ok := <-resultsCh:
			if !ok {
				resultsCh = nil
				continue
			}
			done++
			if progress != nil {
				progress(done, len(files), result.path)
			}
			pending[result.index] = result
			if result.err != nil && shouldPreferScanError(firstErr, result.err) {
				firstErr = result.err
				cancel()
			}
			if firstErr != nil {
				clear(pending)
				continue
			}

			for {
				ordered, exists := pending[nextCommit]
				if !exists || ordered.err != nil {
					break
				}
				delete(pending, nextCommit)
				accumulator.Add(ordered.records)
				nextCommit++
			}

		case <-ctxDone:
			if shouldPreferScanError(firstErr, scanCtx.Err()) {
				firstErr = scanCtx.Err()
			}
			clear(pending)
			ctxDone = nil
		}
	}
	if !jobsClosed {
		close(jobs)
	}
	if firstErr != nil {
		return nil, firstErr
	}
	if nextCommit != len(files) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("scan completed %d of %d packet captures", nextCommit, len(files))
	}
	return accumulator.TakeRecords(), nil
}

func shouldPreferScanError(current, next error) bool {
	if next == nil {
		return false
	}
	if current == nil {
		return true
	}
	if errors.Is(current, context.Canceled) && !errors.Is(next, context.Canceled) {
		return true
	}
	return false
}

type scanFileJob struct {
	index int
	path  string
}

type scanFileResult struct {
	index   int
	path    string
	records []Record
	err     error
}

// Accumulator merges completed per-file trail records in file order while
// retaining the first packet for each TCP SYN attempt and the earliest UDP per tuple.
// Accumulator is not safe for concurrent use; the scan coordinator owns it.
type Accumulator struct {
	seenSYNs   synAttempts
	tcpChunks  []tcpChunk // Completed chunks, in file/packet order.
	tail       tcpChunk   // Active chunk; the first one grows lazily.
	udpRecords map[observedRecordKey]Record
	udpOrder   []observedRecordKey
}

// NewAccumulator returns an empty trail record accumulator.
func NewAccumulator() *Accumulator {
	return &Accumulator{
		udpRecords: make(map[observedRecordKey]Record),
	}
}

// Add merges one completed file in discovered order. ScanPacketBatch and
// Collector.TakePacketBatch provide the headers for replay-wide SYN matching.
// Plain records supplied without their packet headers retain every occurrence.
func (a *Accumulator) Add(records []Record) {
	// The externally visible ordering contract is first-observed TCP attempts in
	// file/packet order followed by first-seen UDP tuples. UDP timestamps may
	// still be replaced by an earlier observation from a later file.
	for _, record := range records {
		if record.Protocol != ProtocolUDP {
			if !a.seenSYNs.keep(&record) {
				continue
			}
			if len(a.tail.slots) == accumulatorChunkRecords {
				// Keep completed chunks in place instead of repeatedly copying
				// the entire capture history into a larger backing array.
				a.tcpChunks = append(a.tcpChunks, a.tail)
				a.tail = tcpChunk{slots: make([]compactTCPRecord, 0, accumulatorChunkRecords)}
			} else if len(a.tail.slots) == cap(a.tail.slots) {
				// Small captures should not allocate a full chunk for one record.
				capacity := max(1, min(2*cap(a.tail.slots), accumulatorChunkRecords))
				grown := make([]compactTCPRecord, len(a.tail.slots), capacity)
				copy(grown, a.tail.slots)
				a.tail.slots = grown
			}
			a.tail.add(record)
			continue
		}
		addEarliestRecord(a.udpRecords, &a.udpOrder, record)
	}
}

// TakeRecords returns the accumulated records and transfers ownership of the
// returned slice to the caller. The accumulator must not be used afterward.
func (a *Accumulator) TakeRecords() []Record {
	a.seenSYNs = nil // The destination allocation can trigger GC.
	tcpCount := len(a.tcpChunks)*accumulatorChunkRecords + len(a.tail.slots)
	var records []Record
	if total := tcpCount + len(a.udpOrder); total > 0 {
		records = make([]Record, tcpCount, total)
	}
	offset := 0
	for i := range a.tcpChunks {
		offset += a.tcpChunks[i].unpackInto(records[offset:])
		a.tcpChunks[i] = tcpChunk{}
	}
	a.tcpChunks = nil
	a.tail.unpackInto(records[offset:])
	a.tail = tcpChunk{}
	for _, key := range a.udpOrder {
		records = append(records, a.udpRecords[key])
	}
	a.udpRecords = nil
	a.udpOrder = nil
	return records
}

// Collector extracts trail evidence from one decoded capture file. Collector
// is owned by one file worker and is not safe for concurrent use.
type Collector struct {
	fleetIdentity  func(Record) string
	syslogCache    *SyslogCache
	syslogEligible func(netip.Addr, netip.Addr) bool
	tcpRecords     []Record
	udpRecords     map[observedRecordKey]Record
	udpOrder       []observedRecordKey
}

// NewCollector returns an empty per-file packet collector.
func NewCollector() *Collector {
	return NewCollectorWithOptions(ScanOptions{})
}

// NewCollectorWithOptions shares positive syslog evidence across file workers.
// Packet admission is the caller's responsibility, before Observe.
func NewCollectorWithOptions(opts ScanOptions) *Collector {
	cache := opts.SyslogCache
	if cache == nil {
		cache = NewSyslogCache()
	}
	return &Collector{fleetIdentity: opts.FleetIdentity, udpRecords: make(map[observedRecordKey]Record), syslogCache: cache, syslogEligible: opts.SyslogEligible}
}

// Observe records eligible raw TCP SYN and UDP evidence from packet. All
// retained fields are copied into stable value types before Observe returns.
// A timestamp error rejects the containing file; callers must not commit its batch.
func (c *Collector) Observe(packet gopacket.Packet) error {
	record, tcp, err := synRecord(packet)
	if err != nil {
		return err
	}
	if tcp != nil {
		if c.fleetIdentity != nil {
			record.FleetIdentity = c.fleetIdentity(record)
			if record.FleetIdentity == "" {
				return nil
			}
		}
		record.hasSYNHeader, record.synSrcPort, record.synSeq = true, uint16(tcp.SrcPort), tcp.Seq
		c.tcpRecords = append(c.tcpRecords, record)
	}
	record, ok, err := udpRecord(packet)
	if err != nil {
		return err
	}
	if ok {
		if c.fleetIdentity != nil {
			record.FleetIdentity = c.fleetIdentity(record)
			if record.FleetIdentity == "" {
				return nil
			}
		}
		if c.syslogEligible != nil && c.syslogEligible(record.SrcAddr(), record.DstAddr()) {
			udp := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
			record.SyslogQualified = c.syslogCache.Qualify(record.DstAddr(), record.DstPort, udp.Payload)
		}
		addEarliestRecord(c.udpRecords, &c.udpOrder, record)
	}
	return nil
}

// TakeRecords returns this file's records and transfers ownership of the
// returned slice to the caller. The collector must not be used afterward.
func (c *Collector) TakeRecords() []Record {
	return singleFileRecords(c.TakePacketBatch())
}

// TakePacketBatch transfers this file's observations, including the TCP wire
// fields needed by Accumulator.Add to recognize retransmissions across files.
func (c *Collector) TakePacketBatch() []Record {
	records := appendOrderedRecords(c.tcpRecords, c.udpRecords, c.udpOrder)
	ApplySyslogQualifications(records, c.syslogCache)
	return records
}

// ScanFile scans one packet capture for trail evidence and returns no partial
// records if the capture cannot be read completely.
func ScanFile(ctx context.Context, path string, admit pcaputil.PacketAdmission) ([]Record, error) {
	return ScanFileWithOptions(ctx, path, ScanOptions{PacketAdmission: admit})
}

// ScanFileWithOptions performs a strict file scan with optional syslog evidence.
func ScanFileWithOptions(ctx context.Context, path string, opts ScanOptions) ([]Record, error) {
	batch, err := ScanPacketBatch(ctx, path, opts)
	if err != nil {
		return nil, err
	}
	return singleFileRecords(batch), nil
}

// ScanPacketBatch strictly reads one file for an ordered Accumulator.Add.
func ScanPacketBatch(ctx context.Context, path string, opts ScanOptions) ([]Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open packet capture %q: %w", path, err)
	}
	defer f.Close()

	src, err := packetSource(f)
	if err != nil {
		return nil, fmt.Errorf("open packet capture reader %q: %w", path, err)
	}
	src.NoCopy = true

	collector := NewCollectorWithOptions(opts)
	packetNumber := 0

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		packet, err := src.NextPacket()
		if err == io.EOF {
			return collector.TakePacketBatch(), nil
		}
		if err != nil {
			return nil, fmt.Errorf("read packet from %q: %w", path, err)
		}
		packetNumber++
		if pcaputil.InvalidTCPHeader(packet) || (opts.PacketAdmission != nil && !opts.PacketAdmission(packet)) {
			continue
		}

		if err := collector.Observe(packet); err != nil {
			return nil, fmt.Errorf("observe packet %d from %q: %w", packetNumber, path, err)
		}
	}
}

func packetSource(f *os.File) (*gopacket.PacketSource, error) {
	r := bufio.NewReader(f)
	magic, _ := r.Peek(4)
	if len(magic) == 4 && magic[0] == 0x0A && magic[1] == 0x0D && magic[2] == 0x0D && magic[3] == 0x0A {
		ngr, err := pcapgo.NewNgReader(r, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			return nil, fmt.Errorf("pcapng reader: %w", err)
		}
		return gopacket.NewPacketSource(ngr, ngr.LinkType()), nil
	}

	pr, err := pcapgo.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("pcap reader: %w", err)
	}
	return gopacket.NewPacketSource(pr, pr.LinkType()), nil
}

func synRecord(packet gopacket.Packet) (Record, *layers.TCP, error) {
	ip4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ip4Layer == nil {
		return Record{}, nil, nil
	}
	ip4, ok := ip4Layer.(*layers.IPv4)
	if !ok {
		return Record{}, nil, nil
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return Record{}, nil, nil
	}
	tcp, ok := tcpLayer.(*layers.TCP)
	if !ok {
		return Record{}, nil, nil
	}
	if !tcp.SYN || tcp.ACK {
		return Record{}, nil, nil
	}

	dstPort := uint16(tcp.DstPort)
	if dstPort == 0 {
		return Record{}, nil, nil
	}

	srcIP, ok := netipAddrFromIPv4(ip4.SrcIP)
	if !ok || !isLocalIPv4(srcIP) {
		return Record{}, nil, nil
	}
	dstIP, ok := netipAddrFromIPv4(ip4.DstIP)
	if !ok {
		return Record{}, nil, nil
	}

	md := packet.Metadata()
	if md == nil {
		return Record{}, nil, nil
	}

	record := Record{SrcIP: srcIP.As4(), DstIP: dstIP.As4(), DstPort: dstPort, Protocol: ProtocolTCP}
	if err := record.SetTimestamp(md.Timestamp); err != nil {
		return Record{}, nil, err
	}
	return record, tcp, nil
}

func udpRecord(packet gopacket.Packet) (Record, bool, error) {
	ip4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ip4Layer == nil {
		return Record{}, false, nil
	}
	ip4, ok := ip4Layer.(*layers.IPv4)
	if !ok {
		return Record{}, false, nil
	}

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return Record{}, false, nil
	}
	udp, ok := udpLayer.(*layers.UDP)
	if !ok {
		return Record{}, false, nil
	}

	dstPort := uint16(udp.DstPort)
	if dstPort == 0 {
		return Record{}, false, nil
	}

	srcIP, ok := netipAddrFromIPv4(ip4.SrcIP)
	if !ok || !isLocalIPv4(srcIP) {
		return Record{}, false, nil
	}
	dstIP, ok := netipAddrFromIPv4(ip4.DstIP)
	if !ok || !isEligibleUDPDestination(dstIP) || srcIP == dstIP {
		return Record{}, false, nil
	}

	md := packet.Metadata()
	if md == nil {
		return Record{}, false, nil
	}

	record := Record{SrcIP: srcIP.As4(), DstIP: dstIP.As4(), DstPort: dstPort, Protocol: ProtocolUDP}
	if err := record.SetTimestamp(md.Timestamp); err != nil {
		return Record{}, false, err
	}
	return record, true, nil
}

type observedRecordKey struct {
	fleetIdentity string
	srcIP         netip.Addr
	dstIP         netip.Addr
	dstPort       uint16
	protocol      Protocol
}

func addEarliestRecord(records map[observedRecordKey]Record, order *[]observedRecordKey, record Record) {
	key := observedRecordKey{
		fleetIdentity: record.FleetIdentity,
		srcIP:         record.SrcAddr(),
		dstIP:         record.DstAddr(),
		dstPort:       record.DstPort,
		protocol:      record.Protocol,
	}
	current, ok := records[key]
	if !ok {
		records[key] = record
		*order = append(*order, key)
		return
	}
	if record.TimeBefore(current) {
		records[key] = record
	}
}

func appendOrderedRecords(prefix []Record, records map[observedRecordKey]Record, order []observedRecordKey) []Record {
	if len(order) == 0 {
		return prefix
	}
	combined := make([]Record, 0, len(prefix)+len(order))
	combined = append(combined, prefix...)
	for _, key := range order {
		combined = append(combined, records[key])
	}
	return combined
}

func isEligibleUDPDestination(ip netip.Addr) bool {
	if !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	return ip != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

func netipAddrFromIPv4(ip net.IP) (netip.Addr, bool) {
	ip4 := ip.To4()
	if ip4 == nil {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}), true
}

// ApplySyslogQualifications propagates evidence discovered by any file worker
// to earlier records. Call after all workers complete, before classification.
func ApplySyslogQualifications(records []Record, cache *SyslogCache) {
	if cache == nil {
		return
	}
	for i := range records {
		if records[i].Protocol == ProtocolUDP {
			records[i].SyslogQualified = cache.Known(records[i].DstAddr(), records[i].DstPort)
		}
	}
}
