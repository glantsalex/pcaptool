package syntrail

import (
	"net/netip"
	"testing"
	"time"
)

func TestSummarySYNRepetitionAcrossFiles(t *testing.T) {
	fleet, err := ParseFleetSubnets([]string{"10.0.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	policy := &SYNSummaryPolicy{Fleet: fleet, FTPPassiveMinPort: 10000}
	var packets []testPacket
	for i := range 1000 {
		packets = append(packets, tcp4PacketWithHeader(time.Unix(int64(i), 0), "10.0.0.1", "203.0.113.10", uint16(40000+i), 443, uint32(i), true, false))
	}
	path := writePCAP(t, packets)
	opt := ScanOptions{SYNSummary: policy, Workers: 8}
	batch, err := ScanPacketBatch(t.Context(), path, opt)
	if err != nil || len(batch) != 1 {
		t.Fatalf("file batch: %d records, %v", len(batch), err)
	}
	a := NewAccumulatorWithSummary(policy)
	for range 8 {
		a.Add(batch)
	}
	if a.RecordCount() != 1 || a.SYNSummaryCount() != 1 || len(a.seenSYNs) != 0 {
		t.Fatalf("global records=%d summary keys=%d retry groups=%d", a.RecordCount(), a.SYNSummaryCount(), len(a.seenSYNs))
	}
	for _, mode := range []struct {
		policy *SYNSummaryPolicy
		want   int
	}{{policy, 1}, {nil, 1000}} {
		opt.SYNSummary = mode.policy
		got, err := ScanFilesWithOptions(t.Context(), []string{path, path}, opt)
		if err != nil || len(got) != mode.want {
			t.Fatalf("overlapping files: got %d records, %v; want %d", len(got), err, mode.want)
		}
	}
}

func TestSummaryDeviceAndFTPScope(t *testing.T) {
	fleet, err := ParseFleetSubnets([]string{"10.0.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		desc     string
		server   string
		port     uint16
		probe    bool
		identity bool
		want     int
	}{
		{"public endpoint", "203.0.113.7", 443, false, true, 1},
		{"private IMSI including unmapped", "192.168.2.8", 443, false, true, 4},
		{"private static IP", "192.168.2.8", 443, false, false, 2},
		{"probe IMSI including unmapped", "192.168.2.8", 443, true, true, 4},
		{"public passive FTP wire pair", "203.0.113.7", 40000, false, true, 2},
		{"public control wire pair", "203.0.113.7", 21, false, true, 2},
		{"private passive pair and identity", "192.168.2.8", 40000, false, true, 5},
		{"fleet internal debug only", "10.0.0.42", 443, false, true, 0},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			p := &SYNSummaryPolicy{Fleet: fleet, FTPControlPorts: map[uint16]struct{}{21: {}}, FTPPassiveMinPort: 10000, CountIMSI: tc.identity}
			a := NewAccumulatorWithSummary(p)
			for _, obs := range []struct{ ip, id string }{{"10.0.0.1", "A"}, {"10.0.0.2", "A"}, {"10.0.0.2", "B"}, {"10.0.0.2", ""}, {"10.0.0.1", ""}} {
				src, dst := netip.MustParseAddr(obs.ip).As4(), netip.MustParseAddr(tc.server).As4()
				if tc.probe {
					src, dst = dst, src
				}
				a.Add([]Record{{SrcIP: src, DstIP: dst, Protocol: ProtocolTCP, DstPort: tc.port, FleetIdentity: obs.id}})
			}
			if n := a.RecordCount(); n != tc.want {
				t.Errorf("records=%d want %d", n, tc.want)
			}
		})
	}
}
