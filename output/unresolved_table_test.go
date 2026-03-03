package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aglants/pcaptool/internal/dns"
)

func TestWriteUnresolvedDNSTable_StacksRepeatedDNSName(t *testing.T) {
	rows := []dns.DNSUnresolvedStat{
		{Name: "q8.public.ocpp-broker.com", IssuerIP: "10.118.165.79", FirstPCAPFile: "a.pcap"},
		{Name: "q8.public.ocpp-broker.com", IssuerIP: "10.118.176.233", FirstPCAPFile: "b.pcap"},
		{Name: "zzz.example.com", IssuerIP: "10.1.1.1", FirstPCAPFile: "c.pcap"},
	}

	var b bytes.Buffer
	if err := WriteUnresolvedDNSTable(&b, rows); err != nil {
		t.Fatalf("WriteUnresolvedDNSTable returned error: %v", err)
	}
	out := b.String()

	if strings.Count(out, "q8.public.ocpp-broker.com") != 1 {
		t.Fatalf("expected stacked DNS name to appear once, output:\n%s", out)
	}
	if strings.Count(out, "zzz.example.com") != 1 {
		t.Fatalf("expected DNS name to appear once, output:\n%s", out)
	}
	if !strings.Contains(out, "10.118.165.79") || !strings.Contains(out, "10.118.176.233") {
		t.Fatalf("expected both issuer rows to be present, output:\n%s", out)
	}
}
