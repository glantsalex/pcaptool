package radius

import (
	"context"
	"encoding/binary"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// The filter only narrows candidates. The existing decoder still validates the
// Accounting Request code, attributes and session information.
const radiusBPFExpression = "udp and (port 1812 or port 1813 or port 1645 or port 1646)"

type radiusPrefilterStats struct {
	scanned, matched, rejected, fallback uint64
	unsupportedFiles, filterErrorFiles   uint64
	compileError                         string
}

// radiusPacketSource is owned by one file worker. In particular pcap.BPF.Matches
// mutates internal scratch storage, so the compiled filter is not shared.
type radiusPacketSource struct {
	ctx        context.Context
	source     gopacket.PacketDataSource
	link       layers.LinkType
	filter     *pcap.BPF
	captureEnd *time.Time
	stats      radiusPrefilterStats
}

func compileRadiusBPF() (*pcap.BPF, error) {
	// Eligibility strips only verified Ethernet/VLAN headers. Compiling for the
	// resulting IPv4 datagram avoids BPF's stateful VLAN-offset expressions.
	return pcap.NewBPF(layers.LinkTypeIPv4, 65535, radiusBPFExpression)
}

func newRadiusPacketSource(ctx context.Context, source gopacket.PacketDataSource, link layers.LinkType, captureEnd *time.Time, compile func() (*pcap.BPF, error)) *radiusPacketSource {
	r := &radiusPacketSource{ctx: ctx, source: source, link: link, captureEnd: captureEnd}
	if link != layers.LinkTypeEthernet {
		r.stats.unsupportedFiles = 1
		return r
	}
	filter, err := compile()
	if err != nil {
		r.stats.filterErrorFiles = 1
		r.stats.compileError = err.Error()
		return r
	}
	if filter == nil {
		r.stats.filterErrorFiles = 1
		r.stats.compileError = "compiler returned no filter"
		return r
	}
	r.filter = filter
	// The gopacket BPF finalizer releases its compiled C program after this
	// file-owned object becomes unreachable. There is no global filter cache.
	return r
}

func (r *radiusPacketSource) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	for {
		// A run of rejected packets must not postpone cancellation until EOF.
		if err := r.ctx.Err(); err != nil {
			return nil, gopacket.CaptureInfo{}, err
		}
		data, ci, err := r.source.ReadPacketData()
		if err != nil {
			return data, ci, err
		}
		r.stats.scanned++
		if ci.Timestamp.After(*r.captureEnd) {
			*r.captureEnd = ci.Timestamp
		}
		if r.filter == nil {
			r.stats.fallback++
			return data, ci, nil
		}
		ip, offset, eligible := radiusFilterIPv4(data, r.link)
		if !eligible {
			r.stats.fallback++
			return data, ci, nil
		}
		filterInfo := ci
		filterInfo.CaptureLength = len(ip)
		filterInfo.Length = max(0, ci.Length-offset)
		if r.filter.Matches(filterInfo, ip) {
			r.stats.matched++
			return data, ci, nil
		}
		r.stats.rejected++
	}
}

// radiusFilterIPv4 recognizes only layouts whose rejection is proven safe for
// the existing decoder. Unknown layouts, tunnels, IPv6, fragments and insufficient
// headers fall back to normal decoding. Returned bytes alias the input only for
// the synchronous BPF check; the admitted packet and metadata remain unchanged.
func radiusFilterIPv4(data []byte, link layers.LinkType) ([]byte, int, bool) {
	if link != layers.LinkTypeEthernet || len(data) < 14 {
		return nil, 0, false
	}
	offset := 14
	etherType := binary.BigEndian.Uint16(data[12:14])
	for tags := 0; etherType == uint16(layers.EthernetTypeDot1Q) || etherType == uint16(layers.EthernetTypeQinQ); tags++ {
		if tags == 2 || len(data) < offset+4 {
			return nil, 0, false
		}
		etherType = binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4
	}
	if etherType != uint16(layers.EthernetTypeIPv4) || len(data) < offset+20 {
		return nil, 0, false
	}
	ip := data[offset:]
	headerLength := int(ip[0]&15) * 4
	if ip[0]>>4 != 4 || headerLength < 20 {
		return nil, 0, false
	}
	if binary.BigEndian.Uint16(ip[6:8])&0x3fff != 0 {
		return nil, 0, false
	}
	minimumTransport := 8
	switch layers.IPProtocol(ip[9]) {
	case layers.IPProtocolTCP:
		minimumTransport = 20
	case layers.IPProtocolUDP:
	default:
		return nil, 0, false // Another IP protocol may encapsulate UDP.
	}
	if len(ip) < headerLength+minimumTransport || int(binary.BigEndian.Uint16(ip[2:4])) < headerLength+minimumTransport {
		return nil, 0, false
	}
	return ip, offset, true
}
