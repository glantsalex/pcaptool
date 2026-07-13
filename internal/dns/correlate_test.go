package dns

import (
	"net"
	"testing"
	"time"

	pce "github.com/aglants/pcaptool/internal/pcap"
)

func TestBuildTransactionsFromEventsSetsDNSAnswerEvidence(t *testing.T) {
	queryTime := time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)
	answerIP := net.ParseIP("8.8.8.8")

	txs, err := BuildTransactionsFromEvents([]pce.Event{
		{
			Timestamp: queryTime,
			Type:      pce.EventDNSQuery,
			SrcIP:     net.ParseIP("10.0.0.10"),
			DstIP:     net.ParseIP("10.0.0.53"),
			DNSID:     0x1234,
			DNSQName:  "api.example.com",
			DNSQTypeA: true,
		},
		{
			Timestamp:   queryTime.Add(10 * time.Millisecond),
			Type:        pce.EventDNSResponse,
			SrcIP:       net.ParseIP("10.0.0.53"),
			DstIP:       net.ParseIP("10.0.0.10"),
			DNSID:       0x1234,
			DNSIsReply:  true,
			DNSAAnswers: []net.IP{answerIP},
		},
	})
	if err != nil {
		t.Fatalf("BuildTransactionsFromEvents() error = %v", err)
	}
	if len(txs) != 1 {
		t.Fatalf("got %d transactions, want 1: %#v", len(txs), txs)
	}
	tx := txs[0]
	if tx.NameEvidence != EvDNSAnswer {
		t.Fatalf("NameEvidence = %v, want EvDNSAnswer", tx.NameEvidence)
	}
	if len(tx.ResolvedIPs) != 1 || !tx.ResolvedIPs[0].Equal(answerIP.To4()) {
		t.Fatalf("ResolvedIPs = %#v, want %s", tx.ResolvedIPs, answerIP.To4())
	}
	if got := tx.ResolvedIPEvidence[answerIP.To4().String()]; got != EvDNSAnswer {
		t.Fatalf("ResolvedIPEvidence = %v, want EvDNSAnswer", got)
	}
}
