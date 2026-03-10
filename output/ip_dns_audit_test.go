package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aglants/pcaptool/internal/dns"
)

func TestWriteIPDNSAppendAuditTable(t *testing.T) {
	rows := []dns.IPDNSAppendAuditRecord{
		{
			DNS:        "ocppj.freshmile.com",
			IP:         "4.178.249.19",
			Evidence:   "dns+conn+synack",
			ObservedAt: "2026-03-08 10:00:00.000000000Z",
			Port:       80,
			IssuerIP:   "10.245.0.209",
			ResolverIP: "8.8.8.8",
			PCAPFile:   "a.pcap",
		},
	}

	var b bytes.Buffer
	if err := WriteIPDNSAppendAuditTable(&b, rows); err != nil {
		t.Fatalf("WriteIPDNSAppendAuditTable error: %v", err)
	}
	got := b.String()
	for _, needle := range []string{
		"DNS Name",
		"ocppj.freshmile.com",
		"4.178.249.19",
		"dns+conn+synack",
		"10.245.0.209",
		"8.8.8.8",
		"a.pcap",
	} {
		if !strings.Contains(got, needle) {
			t.Fatalf("expected output to contain %q, got:\n%s", needle, got)
		}
	}
}
