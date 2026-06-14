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

// ScanFiles scans packet captures for raw observed IPv4 TCP SYN evidence.
func ScanFiles(ctx context.Context, files []string) ([]Record, error) {
	var records []Record
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		fileRecords, err := scanFile(ctx, file)
		if err != nil {
			return nil, err
		}
		records = append(records, fileRecords...)
	}
	return records, nil
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

	var records []Record
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		packet, err := src.NextPacket()
		if err == io.EOF {
			return records, nil
		}
		if err != nil {
			return nil, fmt.Errorf("read packet from %q: %w", path, err)
		}

		record, ok := synRecord(packet)
		if !ok {
			continue
		}
		records = append(records, record)
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
		Timestamp: md.Timestamp.UTC(),
	}, true
}

func netipAddrFromIPv4(ip net.IP) (netip.Addr, bool) {
	ip4 := ip.To4()
	if ip4 == nil {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}), true
}
