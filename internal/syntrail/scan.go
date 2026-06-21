package syntrail

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// ScanFiles scans packet captures for raw observed IPv4 TCP SYN and eligible
// UDP trail evidence.
func ScanFiles(ctx context.Context, files []string) ([]Record, error) {
	var tcpRecords []Record
	udpRecords := make(map[observedRecordKey]Record)
	var udpOrder []observedRecordKey

	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		fileRecords, err := scanFile(ctx, file)
		if err != nil {
			return nil, err
		}
		for _, record := range fileRecords {
			if record.Protocol != ProtocolUDP {
				tcpRecords = append(tcpRecords, record)
				continue
			}
			addEarliestRecord(udpRecords, &udpOrder, record)
		}
	}

	return appendOrderedRecords(tcpRecords, udpRecords, udpOrder), nil
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
