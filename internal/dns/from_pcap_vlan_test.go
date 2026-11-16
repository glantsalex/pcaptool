package dns

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	pcaputil "github.com/aglants/pcaptool/internal/pcap"
	"github.com/aglants/pcaptool/internal/syntrail"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func TestDNSAndSNIVLANAdmission(t *testing.T) {
	base := time.Date(2026, 11, 15, 2, 41, 40, 0, time.UTC)
	fleet, err := syntrail.ParseFleetSubnets([]string{"10.181.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	for _, encap := range []struct {
		name string
		tags []uint16
	}{
		{"untagged", nil}, {"8021q", []uint16{0x8100}}, {"qinq", []uint16{0x88a8, 0x8100}},
	} {
		for _, ng := range []bool{false, true} {
			format := "pcap"
			if ng {
				format = "pcapng"
			}
			t.Run(encap.name+"/"+format, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "traffic."+format)
				packets := [][]byte{
					buildDNSAdmissionPacket(t, buildRawDNSQuery("excluded.example", uint16(layers.DNSTypeA)), "192.0.2.10", "192.0.2.53"),
					buildSNIAdmissionPacket(t, "excluded-sni.example", "192.0.2.10", "203.0.113.20"),
					buildDNSAdmissionPacket(t, buildRawDNSQuery("retained.example", uint16(layers.DNSTypeA)), "10.181.40.62", "192.0.2.53"),
					buildSNIAdmissionPacket(t, "retained-sni.example", "10.181.40.62", "203.0.113.20"),
				}
				f, err := os.Create(path)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { f.Close() })
				var write func(gopacket.CaptureInfo, []byte) error
				var flush func() error
				if ng {
					w, err := pcapgo.NewNgWriter(f, layers.LinkTypeEthernet)
					if err != nil {
						t.Fatal(err)
					}
					write = w.WritePacket
					flush = w.Flush
				} else {
					w := pcapgo.NewWriter(f)
					if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
						t.Fatal(err)
					}
					write = w.WritePacket
				}
				for i, p := range packets {
					for j := len(encap.tags) - 1; j >= 0; j-- {
						tag := make([]byte, 4)
						binary.BigEndian.PutUint16(tag[:2], encap.tags[j])
						binary.BigEndian.PutUint16(tag[2:], 2511)
						wrapped := append([]byte(nil), p[:12]...)
						wrapped = append(wrapped, tag...)
						p = append(wrapped, p[12:]...)
					}
					if err := write(gopacket.CaptureInfo{Timestamp: base.Add(time.Duration(i) * time.Second), CaptureLength: len(p), Length: len(p)}, p); err != nil {
						t.Fatal(err)
					}
				}
				if flush != nil {
					if err := flush(); err != nil {
						t.Fatal(err)
					}
				}
				for _, sni := range []bool{false, true} {
					txs, earliest, _, err := BuildTransactionsWithSNIFromPCAPsWithOptions(context.Background(), []string{path}, sni, false, PacketScanOptions{PacketAdmission: pcaputil.IPv4EndpointAdmission(fleet.Contains)})
					if err != nil {
						t.Fatal(err)
					}
					names := make(map[string]Evidence)
					for _, tx := range txs {
						names[tx.DNSName] = tx.NameEvidence
					}
					want := 1
					if sni {
						want = 2
					}
					_, hasDNS := names["retained.example"]
					if len(names) != want || !hasDNS || (sni && names["retained-sni.example"]&EvSNI == 0) {
						t.Fatalf("SNI=%t: got names/evidence %v, want admitted DNS and optional SNI", sni, names)
					}
					if !earliest.Equal(base.Add(2 * time.Second)) {
						t.Fatalf("earliest=%v", earliest)
					}
				}
			})
		}
	}
}
