package dns

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/aglants/pcaptool/internal/connectivity"
	pcaputil "github.com/aglants/pcaptool/internal/pcap"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func TestDNSAnswerCanAttributeMultipleObservedPorts(t *testing.T) {
	const (
		issuer = "10.245.214.104"
		dst    = "23.97.174.104"
		name   = "time.samsungcloudsolution.com"
	)
	dnsTime := time.Date(2026, 7, 11, 23, 35, 4, 400_000_000, time.UTC)
	t443 := dnsTime.Add(178 * time.Millisecond)
	t80 := dnsTime.Add(183 * time.Millisecond)

	tx := &DNSTransaction{
		RequestTime:  dnsTime,
		IssuerIP:     net.ParseIP(issuer),
		DNSName:      name,
		NameEvidence: EvDNSAnswer,
	}
	tx.AddResolvedIP(net.ParseIP(dst), EvDNSAnswer)

	pcapPath := writeMultiPortBindingPCAP(t, issuer, dst, t443, t80)
	edges, _, err := AttachConnectionsAndCollectEdgesFromPCAPs(
		context.Background(),
		[]string{pcapPath},
		[]*DNSTransaction{tx},
		false,
		false,
		nil,
		false,
		nil,
		nil,
		0,
	)
	if err != nil {
		t.Fatalf("AttachConnectionsAndCollectEdgesFromPCAPs: %v", err)
	}

	if tx.DestinationPort == nil || *tx.DestinationPort != 443 {
		t.Fatalf("legacy DestinationPort = %#v, want 443", tx.DestinationPort)
	}
	if tx.ProtocolL4 != L4ProtoTCP {
		t.Fatalf("legacy ProtocolL4 = %q, want tcp", tx.ProtocolL4)
	}
	if got := len(tx.ObservedEndpointBindings); got != 2 {
		t.Fatalf("observed endpoint bindings len = %d, want 2: %#v", got, tx.ObservedEndpointBindings)
	}
	for _, want := range []ObservedEndpointBinding{
		{DstIP: dst, Protocol: L4ProtoTCP, Port: 443, ObservedAt: t443},
		{DstIP: dst, Protocol: L4ProtoTCP, Port: 80, ObservedAt: t80},
	} {
		if !tx.HasObservedEndpointBinding(want.DstIP, want.Protocol, want.Port, want.ObservedAt) {
			t.Fatalf("missing observed binding %+v in %#v", want, tx.ObservedEndpointBindings)
		}
	}

	opt := DefaultTopologyBuildOptions()
	opt.MaxDNSAge = time.Second
	matrix := BuildNetworkTopologyMatrixEntriesWithOptions([]*DNSTransaction{tx}, edges, nil, nil, opt)
	for _, port := range []uint16{443, 80} {
		row, ok := findTopologyRow(matrix, issuer, dst, "tcp", port)
		if !ok {
			t.Fatalf("missing tcp/%d row; matrix %#v", port, matrix)
		}
		if row.DNSName != name || row.DNSSource != "dns+synack" {
			t.Fatalf("tcp/%d row = %#v, want %s dns+synack; matrix %#v", port, row, name, matrix)
		}
	}
}

func TestAttachConnectionsPacketAdmissionFiltersEdgesAndEarliest(t *testing.T) {
	base := time.Date(2026, 9, 8, 8, 0, 0, 0, time.UTC)
	retainedTS := time.Date(2026, 9, 10, 10, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "fleet-filtered-connections.pcap")
	writeConnectionAdmissionPCAP(t, path, []dnsAdmissionPacket{
		{ts: base, data: buildConnectionInferenceTestTCPPacket(t, "192.168.1.10", "198.51.100.10", 40000, 80, true, false)},
		{ts: base.Add(time.Millisecond), data: buildConnectionInferenceTestTCPPacket(t, "198.51.100.10", "192.168.1.10", 80, 40000, true, true)},
		{ts: retainedTS, data: buildConnectionInferenceTestTCPPacket(t, "10.0.0.1", "203.0.113.10", 40001, 443, true, false)},
		{ts: retainedTS.Add(time.Millisecond), data: buildConnectionInferenceTestTCPPacket(t, "203.0.113.10", "10.0.0.1", 443, 40001, true, true)},
		{ts: retainedTS.Add(time.Second), data: buildConnectionInferenceTestTCPPacket(t, "192.168.1.20", "10.0.0.2", 40002, 22, true, false)},
		{ts: retainedTS.Add(time.Second + time.Millisecond), data: buildConnectionInferenceTestTCPPacket(t, "10.0.0.2", "192.168.1.20", 22, 40002, true, true)},
		{ts: retainedTS.Add(2 * time.Second), data: buildConnectionInferenceTestTCPPacket(t, "10.0.0.1", "10.0.0.2", 40003, 1883, true, false)},
		{ts: retainedTS.Add(2*time.Second + time.Millisecond), data: buildConnectionInferenceTestTCPPacket(t, "10.0.0.2", "10.0.0.1", 1883, 40003, true, true)},
	})

	unfilteredTx := &DNSTransaction{
		RequestTime:  base.Add(-time.Second),
		IssuerIP:     net.ParseIP("192.168.1.10"),
		DNSName:      "correlation.example",
		NameEvidence: EvDNSAnswer,
	}
	unfilteredTx.AddResolvedIP(net.ParseIP("198.51.100.10"), EvDNSAnswer)
	unfiltered, unfilteredFirst, err := AttachConnectionsAndCollectEdgesFromPCAPs(
		context.Background(), []string{path}, []*DNSTransaction{unfilteredTx}, false, false, nil, false, nil, nil, 0,
	)
	if err != nil {
		t.Fatalf("unfiltered connection scan: %v", err)
	}
	if len(unfiltered) != 4 || !unfilteredFirst.Timestamp.Equal(base) {
		t.Fatalf("unfiltered scan = edges %d first %v, want 4/%v", len(unfiltered), unfilteredFirst.Timestamp, base)
	}
	if unfilteredTx.DestinationPort == nil || *unfilteredTx.DestinationPort != 80 || len(unfilteredTx.ObservedEndpointBindings) == 0 {
		t.Fatalf("unfiltered correlation did not use non-fleet connection: %+v", unfilteredTx)
	}

	fleet := map[netip.Addr]struct{}{
		netip.MustParseAddr("10.0.0.1"): {},
		netip.MustParseAddr("10.0.0.2"): {},
	}
	admit := pcaputil.IPv4EndpointAdmission(func(ip netip.Addr) bool {
		_, ok := fleet[ip]
		return ok
	})
	filteredTx := &DNSTransaction{
		RequestTime:  base.Add(-time.Second),
		IssuerIP:     net.ParseIP("192.168.1.10"),
		DNSName:      "correlation.example",
		NameEvidence: EvDNSAnswer,
	}
	filteredTx.AddResolvedIP(net.ParseIP("198.51.100.10"), EvDNSAnswer)
	filtered, filteredFirst, err := AttachConnectionsAndCollectEdgesFromPCAPsWithOptions(
		context.Background(),
		[]string{path},
		[]*DNSTransaction{filteredTx},
		false,
		false,
		nil,
		false,
		nil,
		nil,
		0,
		PacketScanOptions{PacketAdmission: admit},
	)
	if err != nil {
		t.Fatalf("filtered connection scan: %v", err)
	}
	if !filteredFirst.Timestamp.Equal(retainedTS) || filteredFirst.PCAPFile != filepath.Base(path) {
		t.Fatalf("filtered first packet = %+v, want %v/%s", filteredFirst, retainedTS, filepath.Base(path))
	}
	if len(filtered) != 3 {
		t.Fatalf("filtered edges = %+v, want three fleet-related edges", filtered)
	}
	if filteredTx.DestinationPort != nil || len(filteredTx.Candidates) != 0 || len(filteredTx.ObservedEndpointBindings) != 0 {
		t.Fatalf("non-fleet connection leaked into filtered correlation: %+v", filteredTx)
	}
	want := map[string]struct{}{
		"10.0.0.1|203.0.113.10|tcp|443": {},
		"192.168.1.20|10.0.0.2|tcp|22":  {},
		"10.0.0.1|10.0.0.2|tcp|1883":    {},
	}
	for _, edge := range filtered {
		key := edge.IssuerIP + "|" + edge.DstIP + "|" + string(edge.Protocol) + "|" + strconv.Itoa(int(edge.Port))
		if _, ok := want[key]; !ok {
			t.Fatalf("unexpected filtered edge %+v", edge)
		}
		delete(want, key)
	}
	if len(want) != 0 {
		t.Fatalf("missing filtered edges: %v", want)
	}

	noMatch := pcaputil.IPv4EndpointAdmission(func(netip.Addr) bool { return false })
	noEdges, noFirst, err := AttachConnectionsAndCollectEdgesFromPCAPsWithOptions(
		context.Background(), []string{path}, nil, false, false, nil, false, nil, nil, 0,
		PacketScanOptions{PacketAdmission: noMatch},
	)
	if err != nil {
		t.Fatalf("no-match connection scan: %v", err)
	}
	if len(noEdges) != 0 || !noFirst.Timestamp.IsZero() || noFirst.PCAPFile != "" {
		t.Fatalf("no-match scan = edges %+v first %+v, want empty", noEdges, noFirst)
	}
}

func writeConnectionAdmissionPCAP(t *testing.T, path string, packets []dnsAdmissionPacket) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create connection admission pcap: %v", err)
	}
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		f.Close()
		t.Fatalf("write connection admission pcap header: %v", err)
	}
	for i, packet := range packets {
		if err := w.WritePacket(gopacket.CaptureInfo{
			Timestamp: packet.ts, CaptureLength: len(packet.data), Length: len(packet.data),
		}, packet.data); err != nil {
			f.Close()
			t.Fatalf("write connection admission packet %d: %v", i, err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close connection admission pcap: %v", err)
	}
}

func writeMultiPortBindingPCAP(t *testing.T, issuer, dst string, t443, t80 time.Time) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "multi-port-binding.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create multi-port binding pcap: %v", err)
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("write multi-port binding pcap header: %v", err)
	}

	packets := []struct {
		ts   time.Time
		data []byte
	}{
		{ts: t443, data: buildConnectionInferenceTestTCPPacket(t, issuer, dst, 41000, 443, true, false)},
		{ts: t443.Add(10 * time.Millisecond), data: buildConnectionInferenceTestTCPPacket(t, dst, issuer, 443, 41000, true, true)},
		{ts: t80, data: buildConnectionInferenceTestTCPPacket(t, issuer, dst, 41001, 80, true, false)},
		{ts: t80.Add(10 * time.Millisecond), data: buildConnectionInferenceTestTCPPacket(t, dst, issuer, 80, 41001, true, true)},
	}
	for i, packet := range packets {
		if err := w.WritePacket(gopacket.CaptureInfo{
			Timestamp:     packet.ts,
			CaptureLength: len(packet.data),
			Length:        len(packet.data),
		}, packet.data); err != nil {
			t.Fatalf("write multi-port binding packet %d: %v", i, err)
		}
	}
	return path
}

func TestAllowConnectionInferredDNSBackfillWithCSVGuard(t *testing.T) {
	tests := []struct {
		name      string
		candidate string
		ip        string
		ipToDNS   map[string][]string
		wantAllow bool
		wantCSV   string
	}{
		{
			name:      "no csv keeps current inference",
			candidate: "wrong.example.com",
			ip:        "18.244.102.52",
			wantAllow: true,
		},
		{
			name:      "ip absent keeps current inference",
			candidate: "wrong.example.com",
			ip:        "18.244.102.52",
			ipToDNS:   map[string][]string{"18.244.102.53": {"api.store.ccv.eu"}},
			wantAllow: true,
		},
		{
			name:      "same csv dns confirms inference",
			candidate: "api.store.ccv.eu.",
			ip:        "18.244.102.52",
			ipToDNS:   map[string][]string{"18.244.102.52": {"API.Store.CCV.EU"}},
			wantAllow: true,
			wantCSV:   "api.store.ccv.eu",
		},
		{
			name:      "single different csv dns suppresses inference",
			candidate: "wrong.example.com",
			ip:        "18.244.102.52",
			ipToDNS:   map[string][]string{"18.244.102.52": {"api.store.ccv.eu"}},
			wantAllow: false,
			wantCSV:   "api.store.ccv.eu",
		},
		{
			name:      "multi csv containing candidate allows inference",
			candidate: "api.store.ccv.eu",
			ip:        "18.244.102.52",
			ipToDNS: map[string][]string{"18.244.102.52": {
				"mpush.store.ccv.eu",
				"api.store.ccv.eu",
			}},
			wantAllow: true,
			wantCSV:   "api.store.ccv.eu",
		},
		{
			name:      "multi csv without candidate suppresses inference without choosing dns",
			candidate: "wrong.example.com",
			ip:        "18.244.102.52",
			ipToDNS: map[string][]string{"18.244.102.52": {
				"mpush.store.ccv.eu",
				"api.store.ccv.eu",
			}},
			wantAllow: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAllow, gotCSV := allowConnectionInferredDNSBackfill(tt.candidate, tt.ip, tt.ipToDNS)
			if gotAllow != tt.wantAllow || gotCSV != tt.wantCSV {
				t.Fatalf("allowConnectionInferredDNSBackfill() = (%v, %q), want (%v, %q)", gotAllow, gotCSV, tt.wantAllow, tt.wantCSV)
			}
		})
	}
}

func TestSuppressMergedFTPPassiveEdges(t *testing.T) {
	ts := time.Unix(1700000000, 0).UTC()
	edges := []connectivity.Edge{
		{IssuerIP: "10.94.234.132", DstIP: "185.5.124.52", Protocol: connectivity.ProtoTCP, Port: 21, FirstSeen: ts},
		{IssuerIP: "10.94.234.132", DstIP: "185.5.124.52", Protocol: connectivity.ProtoTCP, Port: 49824, FirstSeen: ts.Add(time.Second)},
		{IssuerIP: "10.94.234.132", DstIP: "185.5.124.52", Protocol: connectivity.ProtoTCP, Port: 50081, FirstSeen: ts.Add(2 * time.Second)},
		{IssuerIP: "10.94.234.132", DstIP: "185.5.124.52", Protocol: connectivity.ProtoTCP, Port: 1882, FirstSeen: ts.Add(3 * time.Second)},
		{IssuerIP: "10.94.234.132", DstIP: "194.30.98.208", Protocol: connectivity.ProtoTCP, Port: 6915, FirstSeen: ts.Add(4 * time.Second)},
	}

	got := suppressMergedFTPPassiveEdges(edges, connectivity.DefaultOptions().FTPPassiveMinPort, nil)
	if len(got) != 3 {
		t.Fatalf("expected 3 edges after ftp passive suppression, got %#v", got)
	}
	if got[0].Port != 21 || got[1].Port != 1882 || got[2].Port != 6915 {
		t.Fatalf("expected ports 21, 1882, 6915 after suppression, got %#v", got)
	}
}

func TestSuppressMergedFTPPassiveEdgesCustomControlPort(t *testing.T) {
	ts := time.Unix(1700000100, 0).UTC()
	edges := []connectivity.Edge{
		{IssuerIP: "10.94.234.132", DstIP: "185.5.124.52", Protocol: connectivity.ProtoTCP, Port: 21000, FirstSeen: ts},
		{IssuerIP: "10.94.234.132", DstIP: "185.5.124.52", Protocol: connectivity.ProtoTCP, Port: 49824, FirstSeen: ts.Add(time.Second)},
		{IssuerIP: "10.94.234.132", DstIP: "194.30.98.208", Protocol: connectivity.ProtoTCP, Port: 21, FirstSeen: ts.Add(2 * time.Second)},
		{IssuerIP: "10.94.234.132", DstIP: "194.30.98.208", Protocol: connectivity.ProtoTCP, Port: 50081, FirstSeen: ts.Add(3 * time.Second)},
	}

	got := suppressMergedFTPPassiveEdges(
		edges,
		connectivity.DefaultOptions().FTPPassiveMinPort,
		map[uint16]struct{}{21000: {}},
	)
	if len(got) != 3 {
		t.Fatalf("expected custom control suppression only, got %#v", got)
	}
	if got[0].Port != 21000 || got[1].Port != 21 || got[2].Port != 50081 {
		t.Fatalf("expected ports 21000, 21, 50081 after suppression, got %#v", got)
	}
}

func TestSuppressMergedFTPPassiveEdgesUsesConfiguredMinimum(t *testing.T) {
	tests := []struct {
		name           string
		minPassivePort uint16
		wantDataEdge   bool
	}{
		{name: "custom lower minimum suppresses data edge", minPassivePort: 16000},
		{name: "data edge below custom minimum is retained", minPassivePort: 17000, wantDataEdge: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := time.Unix(1700000200, 0).UTC()
			edges := []connectivity.Edge{
				{IssuerIP: "10.94.234.132", DstIP: "185.5.124.52", Protocol: connectivity.ProtoTCP, Port: 21000, FirstSeen: ts},
				{IssuerIP: "10.94.234.132", DstIP: "185.5.124.52", Protocol: connectivity.ProtoTCP, Port: 16279, FirstSeen: ts.Add(time.Second)},
			}

			got := suppressMergedFTPPassiveEdges(
				edges,
				tt.minPassivePort,
				map[uint16]struct{}{21000: {}},
			)
			wantEdges := 1
			if tt.wantDataEdge {
				wantEdges = 2
			}
			if len(got) != wantEdges {
				t.Fatalf("expected %d edges, got %#v", wantEdges, got)
			}
			gotPorts := make(map[uint16]struct{}, len(got))
			for _, edge := range got {
				gotPorts[edge.Port] = struct{}{}
			}
			if _, ok := gotPorts[21000]; !ok {
				t.Fatalf("expected custom control edge, got %#v", got)
			}
			_, gotDataEdge := gotPorts[16279]
			if gotDataEdge != tt.wantDataEdge {
				t.Fatalf("expected below-threshold data edge, got %#v", got)
			}
		})
	}
}

func TestSuppressMergedFTPPassiveEdgesZeroMinimumUsesDefault(t *testing.T) {
	ts := time.Unix(1700000300, 0).UTC()
	edges := []connectivity.Edge{
		{IssuerIP: "10.94.234.132", DstIP: "185.5.124.52", Protocol: connectivity.ProtoTCP, Port: 21, FirstSeen: ts},
		{IssuerIP: "10.94.234.132", DstIP: "185.5.124.52", Protocol: connectivity.ProtoTCP, Port: 29999, FirstSeen: ts.Add(time.Second)},
		{IssuerIP: "10.94.234.132", DstIP: "185.5.124.52", Protocol: connectivity.ProtoTCP, Port: 30000, FirstSeen: ts.Add(2 * time.Second)},
	}

	got := suppressMergedFTPPassiveEdges(edges, 0, nil)
	if len(got) != 2 {
		t.Fatalf("expected default minimum suppression, got %#v", got)
	}
	if got[0].Port != 21 || got[1].Port != 29999 {
		t.Fatalf("expected ports 21 and 29999 after suppression, got %#v", got)
	}
}

func TestDNSScanCollectsTruncatedQueryAndContinues(t *testing.T) {
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], 0x090a)
	binary.BigEndian.PutUint16(header[2:4], 0x0100)
	binary.BigEndian.PutUint16(header[4:6], 1)
	truncated := append(header, 0x03, 'a', 'p', 'i', 0x07, 'e', 'x')
	malformed := []byte{0x09, 0x0a, 0x01}
	complete := buildRawDNSQuery("complete.example", uint16(layers.DNSTypeA))

	path := filepath.Join(t.TempDir(), "dns-truncated.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create pcap: %v", err)
	}
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		f.Close()
		t.Fatalf("write pcap header: %v", err)
	}
	base := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)
	for i, payload := range [][]byte{truncated, malformed, complete} {
		packetData := buildTestIPv4UDPPacket(t, payload)
		originalLength := len(packetData)
		if i == 0 {
			originalLength += 8
		}
		if err := w.WritePacket(gopacket.CaptureInfo{
			Timestamp:     base.Add(time.Duration(i) * time.Second),
			CaptureLength: len(packetData),
			Length:        originalLength,
		}, packetData); err != nil {
			f.Close()
			t.Fatalf("write pcap packet %d: %v", i, err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close pcap: %v", err)
	}

	txs, _, rows, err := BuildTransactionsWithSNIFromPCAPsWithDiagnostics(
		context.Background(),
		[]string{path},
		false,
		true,
	)
	if err != nil {
		t.Fatalf("scan DNS diagnostics: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("truncated diagnostics = %+v, want one row", rows)
	}
	if rows[0].PCAPFile != filepath.Base(path) || rows[0].IssuerIP != "10.0.0.10" || rows[0].TruncatedDNSName != "api.ex" {
		t.Fatalf("unexpected truncated diagnostic: %+v", rows[0])
	}
	if len(txs) != 1 || txs[0].DNSName != "complete.example" {
		t.Fatalf("scan did not continue to complete DNS query: %+v", txs)
	}

	disabledTxs, _, disabledRows, err := BuildTransactionsWithSNIFromPCAPsWithDiagnostics(
		context.Background(),
		[]string{path},
		false,
		false,
	)
	if err != nil {
		t.Fatalf("scan with diagnostics disabled: %v", err)
	}
	if len(disabledRows) != 0 {
		t.Fatalf("diagnostics disabled returned rows: %+v", disabledRows)
	}
	if len(disabledTxs) != 1 || disabledTxs[0].DNSName != "complete.example" {
		t.Fatalf("diagnostics-disabled scan created a truncated transaction: %+v", disabledTxs)
	}
}

func TestBuildTransactionsWithSNIFromPCAPsPacketAdmissionFiltersEvidenceAndEarliest(t *testing.T) {
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], 0x090a)
	binary.BigEndian.PutUint16(header[2:4], 0x0100)
	binary.BigEndian.PutUint16(header[4:6], 1)
	truncated := append(header, 0x03, 'a', 'p', 'i', 0x07, 'e', 'x')

	base := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	retainedTS := time.Date(2026, 9, 10, 9, 30, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "fleet-filtered-dns.pcap")
	writeDNSAdmissionPCAP(t, path, []dnsAdmissionPacket{
		{ts: base, data: buildDNSAdmissionPacket(t, truncated, "192.168.1.10", "192.0.2.53")},
		{ts: base.Add(time.Second), data: buildDNSAdmissionPacket(t, buildRawDNSQuery("excluded.example", uint16(layers.DNSTypeA)), "192.168.1.10", "192.0.2.53")},
		{ts: base.Add(2 * time.Second), data: buildSNIAdmissionPacket(t, "excluded-sni.example", "192.168.1.10", "198.51.100.20")},
		{ts: retainedTS, data: buildDNSAdmissionPacket(t, buildRawDNSQuery("retained.example", uint16(layers.DNSTypeA)), "10.0.0.1", "192.0.2.53")},
		{ts: retainedTS.Add(time.Second), data: buildSNIAdmissionPacket(t, "retained-sni.example", "10.0.0.1", "203.0.113.20")},
	})

	unfiltered, unfilteredEarliest, unfilteredDiagnostics, err := BuildTransactionsWithSNIFromPCAPsWithDiagnostics(
		context.Background(), []string{path}, true, true,
	)
	if err != nil {
		t.Fatalf("unfiltered DNS scan: %v", err)
	}
	if len(unfiltered) != 4 || len(unfilteredDiagnostics) != 1 || !unfilteredEarliest.Equal(base) {
		t.Fatalf("unfiltered scan = txs %d diagnostics %d earliest %v, want 4/1/%v", len(unfiltered), len(unfilteredDiagnostics), unfilteredEarliest, base)
	}

	fleet := map[netip.Addr]struct{}{netip.MustParseAddr("10.0.0.1"): {}}
	admit := pcaputil.IPv4EndpointAdmission(func(ip netip.Addr) bool {
		_, ok := fleet[ip]
		return ok
	})
	filtered, filteredEarliest, filteredDiagnostics, err := BuildTransactionsWithSNIFromPCAPsWithOptions(
		context.Background(),
		[]string{path},
		true,
		true,
		PacketScanOptions{PacketAdmission: admit},
	)
	if err != nil {
		t.Fatalf("filtered DNS scan: %v", err)
	}
	if len(filtered) != 2 {
		t.Fatalf("filtered transactions = %+v, want retained DNS and SNI only", filtered)
	}
	filteredNames := map[string]Evidence{}
	for _, tx := range filtered {
		filteredNames[tx.DNSName] = tx.NameEvidence
	}
	if _, ok := filteredNames["retained.example"]; !ok || filteredNames["retained-sni.example"]&EvSNI == 0 {
		t.Fatalf("filtered transactions = %+v, want retained DNS and SNI evidence", filtered)
	}
	if _, ok := filteredNames["excluded.example"]; ok {
		t.Fatalf("excluded DNS transaction leaked through packet admission: %+v", filtered)
	}
	if _, ok := filteredNames["excluded-sni.example"]; ok {
		t.Fatalf("excluded SNI transaction leaked through packet admission: %+v", filtered)
	}
	if len(filteredDiagnostics) != 0 {
		t.Fatalf("filtered diagnostics = %+v, want none", filteredDiagnostics)
	}
	if !filteredEarliest.Equal(retainedTS) {
		t.Fatalf("filtered earliest = %v, want %v", filteredEarliest, retainedTS)
	}
}

type dnsAdmissionPacket struct {
	ts   time.Time
	data []byte
}

func writeDNSAdmissionPCAP(t *testing.T, path string, packets []dnsAdmissionPacket) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create DNS admission pcap: %v", err)
	}
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		f.Close()
		t.Fatalf("write DNS admission pcap header: %v", err)
	}
	for i, packet := range packets {
		length := len(packet.data)
		if i == 0 {
			length += 8
		}
		if err := w.WritePacket(gopacket.CaptureInfo{
			Timestamp: packet.ts, CaptureLength: len(packet.data), Length: length,
		}, packet.data); err != nil {
			f.Close()
			t.Fatalf("write DNS admission packet %d: %v", i, err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close DNS admission pcap: %v", err)
	}
}

func buildDNSAdmissionPacket(t *testing.T, payload []byte, src, dst string) []byte {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP(src).To4(), DstIP: net.ParseIP(dst).To4(),
	}
	udp := &layers.UDP{SrcPort: 53000, DstPort: 53}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("set DNS admission UDP checksum layer: %v", err)
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(
		buffer,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth,
		ip,
		udp,
		gopacket.Payload(payload),
	); err != nil {
		t.Fatalf("serialize DNS admission packet: %v", err)
	}
	return buffer.Bytes()
}

func buildSNIAdmissionPacket(t *testing.T, serverName, src, dst string) []byte {
	t.Helper()
	name := []byte(serverName)
	serverNameList := make([]byte, 2+1+2+len(name))
	binary.BigEndian.PutUint16(serverNameList[0:2], uint16(1+2+len(name)))
	serverNameList[2] = 0
	binary.BigEndian.PutUint16(serverNameList[3:5], uint16(len(name)))
	copy(serverNameList[5:], name)

	extensions := make([]byte, 4+len(serverNameList))
	binary.BigEndian.PutUint16(extensions[0:2], 0)
	binary.BigEndian.PutUint16(extensions[2:4], uint16(len(serverNameList)))
	copy(extensions[4:], serverNameList)

	body := make([]byte, 0, 2+32+1+2+2+1+1+2+len(extensions))
	body = append(body, 0x03, 0x03)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)
	body = append(body, 0, 2, 0x13, 0x01)
	body = append(body, 1, 0)
	body = append(body, byte(len(extensions)>>8), byte(len(extensions)))
	body = append(body, extensions...)

	handshake := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	handshake = append(handshake, body...)
	record := []byte{0x16, 0x03, 0x01, byte(len(handshake) >> 8), byte(len(handshake))}
	record = append(record, handshake...)

	eth := &layers.Ethernet{
		SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.ParseIP(src).To4(), DstIP: net.ParseIP(dst).To4(),
	}
	tcp := &layers.TCP{SrcPort: 40000, DstPort: 443, Seq: 1, ACK: true}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("set SNI admission TCP checksum layer: %v", err)
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(
		buffer,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth,
		ip,
		tcp,
		gopacket.Payload(record),
	); err != nil {
		t.Fatalf("serialize SNI admission packet: %v", err)
	}
	return buffer.Bytes()
}
