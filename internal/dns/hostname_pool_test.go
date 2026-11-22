package dns

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestHostnamePoolPreservesEmpty(t *testing.T) {
	pool := NewHostnames()
	if pool.intern("") != 0 || len(pool.byID) != 0 {
		t.Fatal("an absent hostname should not occupy a pool entry")
	}
}

func TestFileMergeSharesDNSAndSNIHostnames(t *testing.T) {
	hostnames := NewHostnames()

	const host = "updates.example"
	const client, server = "10.0.0.1", "192.0.2.2"
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.pcap"), filepath.Join(dir, "b.pcap")
	base := time.Unix(1700000000, 0).UTC()
	query := func(name string) []byte {
		return buildDNSAdmissionPacket(t, buildRawDNSQuery(name, 1), client, server)
	}
	writeConnectionAdmissionPCAP(t, a, []dnsAdmissionPacket{
		{ts: base, data: query("UpDaTeS.Example")},
	})
	writeConnectionAdmissionPCAP(t, b, []dnsAdmissionPacket{
		{ts: base.Add(time.Second), data: query(host)},
		{ts: base.Add(2 * time.Second), data: buildSNIAdmissionPacket(t, host, client, server)},
		{ts: base.Add(3 * time.Second), data: buildSNIAdmissionPacket(t, host+".", client, server)},
	})

	for _, files := range [][]string{{a, b}, {b, a}} {
		txs, _, err := BuildTransactionsWithSNIFromPCAPs(context.Background(), hostnames, files, true)
		if err != nil {
			t.Fatal(err)
		}
		if len(txs) != 4 {
			t.Fatalf("got %d transactions, want 4", len(txs))
		}
		// Independent packets supply independent bytes before the file merge.
		for i, tx := range txs {
			if !tx.RequestTime.utc().Equal(base.Add(time.Duration(i)*time.Second)) || (tx.NameEvidence&EvSNI != 0) != (i >= 2) {
				t.Fatalf("transaction %d lost its timestamp or evidence type", i)
			}
			if i < 3 && (hostnames.name(tx.DNSNameID) != host || tx.DNSNameID != txs[0].DNSNameID) {
				t.Fatalf("transaction %d did not retain the shared hostname", i)
			}
		}
		if hostnames.name(txs[3].DNSNameID) != host+"." {
			t.Fatalf("distinct SNI spelling changed to %q", hostnames.name(txs[3].DNSNameID))
		}
	}
}
