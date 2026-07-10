package dns

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func TestAttachConnectionsInferenceFlagControlsIssuerOnlyFallback(t *testing.T) {
	const (
		issuer   = "10.245.214.104"
		dst      = "23.48.23.56"
		resolver = "192.0.2.53"
	)

	base := time.Date(2026, 7, 8, 2, 5, 56, 0, time.UTC)
	path := writeInferenceTestSYNPCAP(t, issuer, dst, 58073, 443, base.Add(time.Second))
	files := []string{path}

	newTx := func(nameEvidence Evidence, resolved bool) []*DNSTransaction {
		tx := &DNSTransaction{
			RequestTime:  base,
			IssuerIP:     net.ParseIP(issuer),
			DNSName:      "query-only.example.com",
			ResolverIP:   net.ParseIP(resolver),
			NameEvidence: nameEvidence,
		}
		if resolved {
			tx.NameEvidence = EvDNSAnswer
			tx.AddResolvedIP(net.ParseIP(dst), EvDNSAnswer)
		}
		return []*DNSTransaction{tx}
	}

	tests := []struct {
		name           string
		txs            []*DNSTransaction
		infer          bool
		wantSource     string
		wantName       string
		wantResolvedIP bool
	}{
		{
			name:       "disabled skips query-only fallback",
			txs:        newTx(EvNone, false),
			wantSource: "mid-session",
		},
		{
			name:       "disabled skips cname-only no-A fallback",
			txs:        newTx(EvDNSAnswer, false),
			wantSource: "mid-session",
		},
		{
			name:           "opt-in preserves query-only fallback",
			txs:            newTx(EvNone, false),
			infer:          true,
			wantName:       "query-only.example.com",
			wantSource:     "dns+conn+synack",
			wantResolvedIP: true,
		},
		{
			name:           "disabled keeps exact DNS answer correlation",
			txs:            newTx(EvDNSAnswer, true),
			wantName:       "query-only.example.com",
			wantSource:     "dns+synack",
			wantResolvedIP: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			edges, _, err := AttachConnectionsAndCollectEdgesFromPCAPs(
				context.Background(),
				files,
				tt.txs,
				true,
				tt.infer,
				nil,
				false,
				nil,
				nil,
				0,
			)
			if err != nil {
				t.Fatalf("attach connections and collect edges: %v", err)
			}

			rows := BuildNetworkTopologyMatrixEntriesWithOptions(tt.txs, edges, nil, nil, DefaultTopologyBuildOptions())
			if len(rows) != 1 {
				t.Fatalf("got %d rows, want 1: %#v", len(rows), rows)
			}
			row := rows[0]
			if row.DestinationIP != dst || row.Protocol != "tcp" || row.Port != 443 {
				t.Fatalf("unexpected endpoint row: %#v", row)
			}
			if row.DNSName != tt.wantName || row.DNSSource != tt.wantSource {
				t.Fatalf("row attribution=(%q,%q), want (%q,%q): %#v", row.DNSName, row.DNSSource, tt.wantName, tt.wantSource, rows)
			}
			if got := containsConnectionInferenceTestIP(tt.txs[0].ResolvedIPs, dst); got != tt.wantResolvedIP {
				t.Fatalf("resolved IP present=%v, want %v; tx=%#v", got, tt.wantResolvedIP, tt.txs[0])
			}
		})
	}
}

func writeInferenceTestSYNPCAP(t *testing.T, issuer, dst string, srcPort, dstPort uint16, synTime time.Time) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "connection-inference.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create pcap: %v", err)
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("write pcap header: %v", err)
	}

	packets := []struct {
		ts   time.Time
		data []byte
	}{
		{ts: synTime, data: buildConnectionInferenceTestTCPPacket(t, issuer, dst, srcPort, dstPort, true, false)},
		{ts: synTime.Add(10 * time.Millisecond), data: buildConnectionInferenceTestTCPPacket(t, dst, issuer, dstPort, srcPort, true, true)},
	}
	for i, packet := range packets {
		if err := w.WritePacket(gopacket.CaptureInfo{
			Timestamp:     packet.ts,
			CaptureLength: len(packet.data),
			Length:        len(packet.data),
		}, packet.data); err != nil {
			t.Fatalf("write packet %d: %v", i, err)
		}
	}
	return path
}

func buildConnectionInferenceTestTCPPacket(t *testing.T, srcIP, dstIP string, srcPort, dstPort uint16, syn, ack bool) []byte {
	t.Helper()

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0, 1, 2, 3, 4, 5},
		DstMAC:       net.HardwareAddr{6, 7, 8, 9, 10, 11},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.ParseIP(srcIP).To4(),
		DstIP:    net.ParseIP(dstIP).To4(),
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     1000,
		Ack:     1001,
		SYN:     syn,
		ACK:     ack,
		Window:  29200,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip4); err != nil {
		t.Fatalf("set TCP checksum network layer: %v", err)
	}

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(
		buf,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth,
		ip4,
		tcp,
	); err != nil {
		t.Fatalf("serialize TCP packet: %v", err)
	}
	return buf.Bytes()
}

func containsConnectionInferenceTestIP(ips []net.IP, want string) bool {
	parsed := net.ParseIP(want)
	for _, ip := range ips {
		if ip != nil && ip.Equal(parsed) {
			return true
		}
	}
	return false
}
