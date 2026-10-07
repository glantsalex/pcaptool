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
	// Workers is the maximum number of capture files scanned concurrently.
	// Values <= 1 preserve the historical sequential scan behavior.
	Workers int

	// Progress is called after each file scan completes. It is optional and is
	// invoked from the coordinating goroutine, not from worker goroutines.
	Progress ScanProgressFunc

	// PacketAdmission, when non-nil, is applied immediately after packet
	// decoding. Rejected packets cannot contribute trail evidence.
	PacketAdmission pcaputil.PacketAdmission
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
	if opts.Workers <= 1 {
		return scanFilesSequential(ctx, files, opts.Progress, opts.PacketAdmission)
	}
	return scanFilesConcurrent(ctx, files, opts.Workers, opts.Progress, opts.PacketAdmission)
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
		fileRecords, err := ScanFile(ctx, file, admit)
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
	return scanFilesConcurrentWithScanner(ctx, files, workers, progress, admit, ScanFile)
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
// preserving TCP observations and globally deduplicating UDP tuples.
// Accumulator is not safe for concurrent use; the scan coordinator owns it.
type Accumulator struct {
	tcpRecords []Record
	udpRecords map[observedRecordKey]Record
	udpOrder   []observedRecordKey
}

// NewAccumulator returns an empty trail record accumulator.
func NewAccumulator() *Accumulator {
	return &Accumulator{
		udpRecords: make(map[observedRecordKey]Record),
	}
}

// Add merges one completed file's records. Callers must add files in the
// discovered file order to preserve externally visible trail ordering.
func (a *Accumulator) Add(records []Record) {
	// The externally visible ordering contract is all TCP observations in
	// file/packet order followed by first-seen UDP tuples. UDP timestamps may
	// still be replaced by an earlier observation from a later file.
	for _, record := range records {
		if record.Protocol != ProtocolUDP {
			a.tcpRecords = append(a.tcpRecords, record)
			continue
		}
		addEarliestRecord(a.udpRecords, &a.udpOrder, record)
	}
}

// TakeRecords returns the accumulated records and transfers ownership of the
// returned slice to the caller. The accumulator must not be used afterward.
func (a *Accumulator) TakeRecords() []Record {
	for _, key := range a.udpOrder {
		a.tcpRecords = append(a.tcpRecords, a.udpRecords[key])
	}
	records := a.tcpRecords
	a.tcpRecords = nil
	a.udpRecords = nil
	a.udpOrder = nil
	return records
}

// Collector extracts trail evidence from one decoded capture file. Collector
// is owned by one file worker and is not safe for concurrent use.
type Collector struct {
	tcpRecords []Record
	udpRecords map[observedRecordKey]Record
	udpOrder   []observedRecordKey
}

// NewCollector returns an empty per-file packet collector.
func NewCollector() *Collector {
	return &Collector{udpRecords: make(map[observedRecordKey]Record)}
}

// Observe records eligible raw TCP SYN and UDP evidence from packet. All
// retained fields are copied into stable value types before Observe returns.
func (c *Collector) Observe(packet gopacket.Packet) {
	if record, ok := synRecord(packet); ok {
		c.tcpRecords = append(c.tcpRecords, record)
	}
	if record, ok := udpRecord(packet); ok {
		addEarliestRecord(c.udpRecords, &c.udpOrder, record)
	}
}

// TakeRecords returns this file's records and transfers ownership of the
// returned slice to the caller. The collector must not be used afterward.
func (c *Collector) TakeRecords() []Record {
	return appendOrderedRecords(c.tcpRecords, c.udpRecords, c.udpOrder)
}

// ScanFile scans one packet capture for trail evidence and returns no partial
// records if the capture cannot be read completely.
func ScanFile(ctx context.Context, path string, admit pcaputil.PacketAdmission) ([]Record, error) {
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

	collector := NewCollector()

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		packet, err := src.NextPacket()
		if err == io.EOF {
			return collector.TakeRecords(), nil
		}
		if err != nil {
			return nil, fmt.Errorf("read packet from %q: %w", path, err)
		}
		if admit != nil && !admit(packet) {
			continue
		}

		collector.Observe(packet)
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

func synRecord(packet gopacket.Packet) (Record, bool) {
	ip4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ip4Layer == nil {
		return Record{}, false
	}
	ip4, ok := ip4Layer.(*layers.IPv4)
	if !ok {
		return Record{}, false
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return Record{}, false
	}
	tcp, ok := tcpLayer.(*layers.TCP)
	if !ok {
		return Record{}, false
	}
	if !tcp.SYN || tcp.ACK {
		return Record{}, false
	}

	dstPort := uint16(tcp.DstPort)
	if dstPort == 0 {
		return Record{}, false
	}

	srcIP, ok := netipAddrFromIPv4(ip4.SrcIP)
	if !ok || !isLocalIPv4(srcIP) {
		return Record{}, false
	}
	dstIP, ok := netipAddrFromIPv4(ip4.DstIP)
	if !ok {
		return Record{}, false
	}

	md := packet.Metadata()
	if md == nil {
		return Record{}, false
	}

	return Record{
		SrcIP:     srcIP,
		DstIP:     dstIP,
		DstPort:   dstPort,
		Protocol:  ProtocolTCP,
		Timestamp: md.Timestamp.UTC(),
	}, true
}

func udpRecord(packet gopacket.Packet) (Record, bool) {
	ip4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ip4Layer == nil {
		return Record{}, false
	}
	ip4, ok := ip4Layer.(*layers.IPv4)
	if !ok {
		return Record{}, false
	}

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return Record{}, false
	}
	udp, ok := udpLayer.(*layers.UDP)
	if !ok {
		return Record{}, false
	}

	dstPort := uint16(udp.DstPort)
	if dstPort == 0 {
		return Record{}, false
	}

	srcIP, ok := netipAddrFromIPv4(ip4.SrcIP)
	if !ok || !isLocalIPv4(srcIP) {
		return Record{}, false
	}
	dstIP, ok := netipAddrFromIPv4(ip4.DstIP)
	if !ok || !isEligibleUDPDestination(dstIP) || srcIP == dstIP {
		return Record{}, false
	}

	md := packet.Metadata()
	if md == nil {
		return Record{}, false
	}

	return Record{
		SrcIP:     srcIP,
		DstIP:     dstIP,
		DstPort:   dstPort,
		Protocol:  ProtocolUDP,
		Timestamp: md.Timestamp.UTC(),
	}, true
}

type observedRecordKey struct {
	srcIP    netip.Addr
	dstIP    netip.Addr
	dstPort  uint16
	protocol Protocol
}

func addEarliestRecord(records map[observedRecordKey]Record, order *[]observedRecordKey, record Record) {
	key := observedRecordKey{
		srcIP:    record.SrcIP,
		dstIP:    record.DstIP,
		dstPort:  record.DstPort,
		protocol: record.Protocol,
	}
	current, ok := records[key]
	if !ok {
		records[key] = record
		*order = append(*order, key)
		return
	}
	if record.Timestamp.Before(current.Timestamp) {
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
