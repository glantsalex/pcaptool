package dns

import (
	"bytes"
	"hash/fnv"
	"math"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"
)

func TestTransactionHostnameIDs(t *testing.T) {
	h := NewHostnames()
	const name = "updates.example"
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(name))
	if id := h.intern(canonicalDNSName("UPDATES.Example.")); id != hash.Sum64() || h.name(id) != name {
		t.Fatalf("normalized name %q has ID %x, want %x", h.name(id), id, hash.Sum64())
	}
	if h.intern("") != 0 || h.name(0) != "" || len(h.byID) != 1 {
		t.Fatal("empty name should use the reserved ID")
	}
}

func TestConcurrentHostnameCollision(t *testing.T) {
	h := NewHostnames()
	names := []string{"a.example", "b.example", "c.example"}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(offset int) {
			defer wg.Done()
			for i := 0; i < 300; i++ {
				name := names[(i+offset)%len(names)]
				id := h.internAt(math.MaxUint64, name)
				if id == 0 || h.name(id) != name {
					t.Errorf("collision lost %q at ID %x", name, id)
					return
				}
			}
		}(i)
	}
	wg.Wait()
	if len(h.byID) != len(names) {
		t.Fatalf("stored %d names, want %d", len(h.byID), len(names))
	}
	a := &DNSTransaction{DNSNameID: h.internAt(math.MaxUint64, "a.example")}
	b := &DNSTransaction{DNSNameID: h.internAt(math.MaxUint64, "b.example")}
	if !transactionTieLess(h, a, b) || transactionTieLess(h, b, a) {
		t.Fatal("tie order must use hostname spelling")
	}
}

func TestTransactionAddressesOwnWireBytes(t *testing.T) {
	for _, ip := range []net.IP{nil, {}, {0, 0, 0, 0}, {192, 0, 2, 3}, net.ParseIP("192.0.2.3"), net.ParseIP("2001:db8::1")} {
		issuer, resolver := slices.Clone(ip), slices.Clone(ip)
		packed := makeEndpoints(issuer, resolver)
		clear(issuer)
		clear(resolver)
		for _, got := range []net.IP{packed.issuerIP(), packed.resolverIP()} {
			if (got == nil) != (ip == nil) || !bytes.Equal(got, ip) {
				t.Fatalf("got %v (%d bytes), want %v (%d bytes)", got, len(got), ip, len(ip))
			}
		}
		if ip.To4() != nil && packed.wide != nil {
			t.Fatal("unexpected IPv4 sidecar")
		}
		packed.setResolver(net.IP{1, 2, 3, 4})
		if !bytes.Equal(packed.resolverIP(), []byte{1, 2, 3, 4}) || !bytes.Equal(packed.issuerIP(), ip) {
			t.Fatal("resolver update changed an endpoint incorrectly")
		}
	}
}

func TestTransactionTimestampAndProtocol(t *testing.T) {
	if !(captureTime{}).utc().IsZero() {
		t.Fatal("zero record should have a missing time")
	}
	var prev captureTime
	for _, ts := range []time.Time{{}, time.Unix(-1, 999999999), time.Unix(0, 0), time.Unix(0, 1), time.Date(2399, 1, 2, 3, 4, 5, 987654321, time.UTC)} {
		w := wireTime(ts)
		if got := w.utc(); !got.Equal(ts) || got.Location() != time.UTC {
			t.Fatalf("timestamp %v round-tripped to %v", ts, got)
		}
		if !ts.IsZero() && prev.compare(w) >= 0 {
			t.Fatalf("time ordering at %v", ts)
		}
		prev = w
	}
	for p, n := range map[L4Proto]wireProtocol{L4ProtoUnknown: 0, L4ProtoTCP: 6, L4ProtoUDP: 17} {
		if protocolNumber(p) != n || n.protocol() != p {
			t.Fatalf("incorrect mapping for %q/%d", p, n)
		}
	}
}

func TestHostnameTableOwnsOnlyNewNames(t *testing.T) {
	h := NewHostnames()
	name := strings.Clone("device.example")
	id := h.intern(name)
	if unsafe.StringData(h.name(id)) == unsafe.StringData(name) {
		t.Fatal("dictionary kept caller's backing storage")
	}
	if got := testing.AllocsPerRun(1000, func() {
		if h.intern(name) != id {
			panic("unstable ID")
		}
	}); got != 0 {
		t.Fatalf("interning a known name allocated %v times", got)
	}
}

func TestDNSScanRejectsMixedRunDictionaries(t *testing.T) {
	facts := NewFactCollection(NewHostnames(), nil, false, 0)
	if _, _, _, err := BuildTransactionsWithSNIFromPCAPsWithOptions(t.Context(), NewHostnames(), nil, false, false, PacketScanOptions{Facts: facts}); err == nil {
		t.Fatal("scan accepted inconsistent hostname ownership")
	}
}
