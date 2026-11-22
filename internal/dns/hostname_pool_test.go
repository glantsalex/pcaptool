package dns

import (
	"context"
	"path/filepath"
	"testing"
	"time"
	"unsafe"
)

func TestHostnamePoolPreservesEmpty(t *testing.T) {
	pool := make(hostnamePool)
	if pool.share("") != "" || len(pool) != 0 {
		t.Fatal("an absent hostname should not occupy a pool entry")
	}
}

func TestFileMergeSharesDNSAndSNIHostnames(t *testing.T) {
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
		txs, _, err := BuildTransactionsWithSNIFromPCAPs(context.Background(), files, true)
		if err != nil {
			t.Fatal(err)
		}
		if len(txs) != 4 {
			t.Fatalf("got %d transactions, want 4", len(txs))
		}
		// Independent packets supply independent bytes before the file merge.
		for i, tx := range txs {
			if !tx.RequestTime.Equal(base.Add(time.Duration(i)*time.Second)) || (tx.NameEvidence&EvSNI != 0) != (i >= 2) {
				t.Fatalf("transaction %d lost its timestamp or evidence type", i)
			}
			if i < 3 && (tx.DNSName != host || unsafe.StringData(tx.DNSName) != unsafe.StringData(txs[0].DNSName)) {
				t.Fatalf("transaction %d did not retain the shared hostname", i)
			}
		}
		if txs[3].DNSName != host+"." {
			t.Fatalf("distinct SNI spelling changed to %q", txs[3].DNSName)
		}
	}
}
