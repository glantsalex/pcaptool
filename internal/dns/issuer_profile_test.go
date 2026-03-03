package dns

import (
	"net"
	"testing"
)

func TestComputeIssuerProfile_SortByTotalDNSThenIssuer(t *testing.T) {
	mk := func(issuer string, n int) []*DNSTransaction {
		out := make([]*DNSTransaction, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, &DNSTransaction{
				IssuerIP: net.ParseIP(issuer),
				DNSName:  "x.example",
			})
		}
		return out
	}

	var txs []*DNSTransaction
	txs = append(txs, mk("10.0.0.2", 3)...)
	txs = append(txs, mk("10.0.0.1", 3)...)
	txs = append(txs, mk("10.0.0.3", 1)...)

	prof := ComputeIssuerProfile(txs)
	if len(prof) != 3 {
		t.Fatalf("len(prof)=%d, want 3", len(prof))
	}

	if prof[0].IssuerIP != "10.0.0.1" || prof[0].TotalDNS != 3 {
		t.Fatalf("row0=%+v, want issuer 10.0.0.1 total 3", prof[0])
	}
	if prof[1].IssuerIP != "10.0.0.2" || prof[1].TotalDNS != 3 {
		t.Fatalf("row1=%+v, want issuer 10.0.0.2 total 3", prof[1])
	}
	if prof[2].IssuerIP != "10.0.0.3" || prof[2].TotalDNS != 1 {
		t.Fatalf("row2=%+v, want issuer 10.0.0.3 total 1", prof[2])
	}
}
