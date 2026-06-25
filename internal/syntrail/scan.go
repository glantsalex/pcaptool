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
		return scanFilesSequential(ctx, files, opts.Progress)
	}
	return scanFilesConcurrent(ctx, files, opts.Workers, opts.Progress)
}

func scanFilesSequential(ctx context.Context, files []string, progress ScanProgressFunc) ([]Record, error) {
	results := make([]scanFileResult, len(files))
	for i, file := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fileRecords, err := scanFile(ctx, file)
		if progress != nil {
			progress(i+1, len(files), file)
		}
		if err != nil {
			return nil, err
		}
		results[i] = scanFileResult{
			index:   i,
			path:    file,
			records: fileRecords,
		}
	}
	return mergeScanFileResults(results), nil
}

func scanFilesConcurrent(ctx context.Context, files []string, workers int, progress ScanProgressFunc) ([]Record, error) {
	if workers > len(files) {
		workers = len(files)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs := make(chan scanFileJob)
	resultsCh := make(chan scanFileResult, len(files))

	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			for job := range jobs {
				if err := ctx.Err(); err != nil {
					resultsCh <- scanFileResult{index: job.index, path: job.path, err: err}
					continue
				}

				records, err := scanFile(ctx, job.path)
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
		defer close(jobs)
		for i, file := range files {
			if err := ctx.Err(); err != nil {
				return
			}
			select {
			case jobs <- scanFileJob{index: i, path: file}:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	results := make([]scanFileResult, len(files))
	seen := make([]bool, len(files))
	var firstErr error
	done := 0
	for result := range resultsCh {
		if result.index >= 0 && result.index < len(files) {
			results[result.index] = result
			seen[result.index] = true
		}
		done++
		if progress != nil {
			progress(done, len(files), result.path)
		}
		if result.err != nil && shouldPreferScanError(firstErr, result.err) {
			firstErr = result.err
			cancel()
		}
	}
	if firstErr != nil {
		return nil, firstErr
	}
	for i := range files {
		if !seen[i] {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
	}
	return mergeScanFileResults(results), nil
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

func mergeScanFileResults(results []scanFileResult) []Record {
	var tcpRecords []Record
	udpRecords := make(map[observedRecordKey]Record)
	var udpOrder []observedRecordKey

	for _, result := range results {
		for _, record := range result.records {
			if record.Protocol != ProtocolUDP {
				tcpRecords = append(tcpRecords, record)
				continue
			}
			addEarliestRecord(udpRecords, &udpOrder, record)
		}
	}

	return appendOrderedRecords(tcpRecords, udpRecords, udpOrder)
}

func scanFile(ctx context.Context, path string) ([]Record, error) {
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

	var tcpRecords []Record
	udpRecords := make(map[observedRecordKey]Record)
	var udpOrder []observedRecordKey

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		packet, err := src.NextPacket()
		if err == io.EOF {
			return appendOrderedRecords(tcpRecords, udpRecords, udpOrder), nil
		}
		if err != nil {
			return nil, fmt.Errorf("read packet from %q: %w", path, err)
		}

		if record, ok := synRecord(packet); ok {
			tcpRecords = append(tcpRecords, record)
		}
		if record, ok := udpRecord(packet); ok {
			addEarliestRecord(udpRecords, &udpOrder, record)
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
