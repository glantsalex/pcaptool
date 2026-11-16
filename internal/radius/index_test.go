package radius

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func TestSessionWindowsIncompleteEvidenceAndReassignment(t *testing.T) {
	const a = "123456789012345"
	const b = "223456789012345"
	ip := netip.MustParseAddr("10.1.0.1")
	msg := func(at int64, imsi string, status radStatus, duration uint32, present bool) radMsg {
		return radMsg{tsMs: at, imsi: imsi, ip: ip.String(), sid: imsi, status: status, sessTimeSec: duration, hasSessionTime: present}
	}
	tests := []struct {
		name   string
		msgs   []radMsg
		checks map[int64]string
	}{
		{"start only", []radMsg{msg(10000, a, radStart, 0, false)}, map[int64]string{9999: "", 10000: a, 99999: a, 100001: ""}},
		{"interim duration", []radMsg{msg(20000, a, radInterm, 10, true)}, map[int64]string{9999: "", 10000: a, 90000: a}},
		{"stop duration", []radMsg{msg(20000, a, radStop, 10, true)}, map[int64]string{9999: "", 10000: a, 20000: a, 20001: ""}},
		{"interim missing duration", []radMsg{msg(20000, a, radInterm, 0, false)}, map[int64]string{19999: "", 20000: a, 90000: a}},
		{"stop missing duration", []radMsg{msg(20000, a, radStop, 0, false)}, map[int64]string{19999: "", 20000: a, 20001: ""}},
		{"interim explicit zero", []radMsg{msg(20000, a, radInterm, 0, true)}, map[int64]string{19999: "", 20000: a, 90000: a}},
		{"delayed start preserves earlier evidence", []radMsg{msg(20000, a, radInterm, 10, true), msg(21000, a, radStart, 0, false)}, map[int64]string{9999: "", 10000: a, 20000: a, 90000: a}},
		{"simultaneous assignments are ambiguous", []radMsg{msg(10000, a, radStart, 0, false), msg(10000, b, radStart, 0, false)}, map[int64]string{9999: "", 10000: "", 90000: ""}},
		{"delayed interim does not reopen stopped session", []radMsg{msg(20000, a, radStop, 10, true), msg(21000, a, radInterm, 11, true)}, map[int64]string{10000: a, 20000: a, 20001: "", 21000: ""}},
		{"full session", []radMsg{msg(10000, a, radStart, 0, false), msg(20000, a, radInterm, 10, true), msg(30000, a, radStop, 20, true)}, map[int64]string{9999: "", 10000: a, 30000: a, 30001: ""}},
		{"reassigned IP", []radMsg{msg(10000, a, radStart, 0, false), msg(30000, b, radStart, 0, false)}, map[int64]string{29999: a, 30000: b, 90000: b}},
		{"contradictory overlap", []radMsg{msg(10000, a, radStart, 0, false), msg(20000, b, radStart, 0, false), msg(30000, a, radStop, 20, true)}, map[int64]string{19999: a, 20000: "", 30000: "", 30001: b}},
		{"interim then stop missing start", []radMsg{msg(20000, a, radInterm, 10, true), msg(30000, a, radStop, 20, true)}, map[int64]string{10000: a, 30000: a, 30001: ""}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idx := NewIMSIIndex()
			idx.byIP[ip] = buildSessionWindows(tt.msgs, 100000)
			for ts, want := range tt.checks {
				got, ok := idx.LookupAddr(ip, time.UnixMilli(ts))
				if got != want || ok != (want != "") {
					t.Fatalf("at %d: (%q,%v), want %q; windows=%+v", ts, got, ok, want, idx.byIP[ip])
				}
			}
		})
	}
}

func TestBuildIndexUsesAllCaptureTimesAndIsIndependentOfFileOrder(t *testing.T) {
	base := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	a := radiusAdmissionPacket{src: "192.0.2.1", dst: "192.0.2.2", framedIP: "10.1.0.1", imsi: "123456789012345", sessionID: "a", ts: base}
	b := a
	b.imsi = "223456789012345"
	b.sessionID = "b"
	b.ts = base.Add(time.Hour)
	tail := a
	tail.imsi = ""
	tail.ts = base.Add(2 * time.Hour)
	f1, f2 := filepath.Join(t.TempDir(), "one.pcap"), filepath.Join(t.TempDir(), "two.pcap")
	writeRadiusAdmissionPCAP(t, f1, []radiusAdmissionPacket{b, tail})
	writeRadiusAdmissionPCAP(t, f2, []radiusAdmissionPacket{a, a})
	one, err := BuildIMSIIndexFromPCAPs(context.Background(), []string{f1, f2})
	if err != nil {
		t.Fatal(err)
	}
	two, err := BuildIMSIIndexFromPCAPs(context.Background(), []string{f2, f1})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(one.byIP, two.byIP) {
		t.Fatalf("file ordering changes index: %+v vs %+v", one.byIP, two.byIP)
	}
	ip := netip.MustParseAddr(a.framedIP)
	for _, tt := range []struct {
		offset time.Duration
		want   string
	}{{30 * time.Minute, a.imsi}, {time.Hour, b.imsi}, {119 * time.Minute, b.imsi}, {121 * time.Minute, ""}} {
		got, _ := one.LookupAddr(ip, base.Add(tt.offset))
		if got != tt.want {
			t.Fatalf("at %s got %q want %q", tt.offset, got, tt.want)
		}
	}
}

func TestBuildIndexRejectsIncompleteCaptureAndCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if idx, err := BuildIMSIIndexFromPCAPs(ctx, nil); err == nil || idx != nil {
		t.Fatal("canceled scan accepted")
	}
	path := filepath.Join(t.TempDir(), "bad.pcap")
	writeRadiusAdmissionPCAP(t, path, []radiusAdmissionPacket{{src: "192.0.2.1", dst: "192.0.2.2", framedIP: "10.1.0.1", imsi: "123456789012345", sessionID: "a"}})
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, raw[:len(raw)-3], 0600); err != nil {
		t.Fatal(err)
	}
	if idx, err := BuildIMSIIndexFromPCAPs(context.Background(), []string{path}); err == nil || idx != nil {
		t.Fatal("truncated scan returned an index")
	}
}

func TestRadiusBatchBoundaries(t *testing.T) {
	for _, n := range []int{0, 1, 255, 256, 257} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			packets := make([]radiusAdmissionPacket, n)
			for i := range packets {
				packets[i] = radiusAdmissionPacket{src: "192.0.2.1", dst: "192.0.2.2", framedIP: "10.1.0.1", imsi: "123456789012345", sessionID: "s"}
			}
			path := filepath.Join(t.TempDir(), "batch.pcap")
			writeRadiusAdmissionPCAP(t, path, packets)
			if got := len(collectRadiusMessages(t, path)); got != n {
				t.Fatalf("got %d, want %d", got, n)
			}
		})
	}
}

func TestRadiusPCAPNGAndPCAPReconstructOrphanStop(t *testing.T) {
	base := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	duration := uint32(20)
	packet := radiusAdmissionPacket{src: "192.0.2.1", dst: "192.0.2.2", framedIP: "10.1.0.1", imsi: "123456789012345", sessionID: "a", status: acctStatusStop, duration: &duration, ts: base.Add(30 * time.Second)}
	classic := filepath.Join(t.TempDir(), "capture.pcap")
	writeRadiusAdmissionPCAP(t, classic, []radiusAdmissionPacket{packet})
	ng := filepath.Join(t.TempDir(), "capture.pcapng")
	f, err := os.Create(ng)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	w, err := pcapgo.NewNgWriter(f, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	data := buildRadiusAdmissionPacket(t, packet, 1)
	if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: packet.ts, CaptureLength: len(data), Length: len(data)}, data); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{classic, ng} {
		t.Run(filepath.Ext(path), func(t *testing.T) {
			idx, err := BuildIMSIIndexFromPCAPs(context.Background(), []string{path})
			if err != nil {
				t.Fatal(err)
			}
			for second, want := range map[int]string{9: "", 10: packet.imsi, 30: packet.imsi, 31: ""} {
				got, _ := idx.LookupAddr(netip.MustParseAddr(packet.framedIP), base.Add(time.Duration(second)*time.Second))
				if got != want {
					t.Fatalf("at %ds got %q, want %q", second, got, want)
				}
			}
		})
	}
}
