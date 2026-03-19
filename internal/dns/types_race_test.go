package dns

import (
	"net"
	"sync"
	"testing"
	"time"
)

func TestDNSTransactionResolvedIPAccessConcurrent(t *testing.T) {
	tx := &DNSTransaction{
		RequestTime:  time.Now(),
		IssuerIP:     net.ParseIP("10.0.0.1"),
		DNSName:      "example.com",
		NameEvidence: EvDNSAnswer,
	}

	ips := []net.IP{
		net.ParseIP("1.1.1.1"),
		net.ParseIP("1.1.1.2"),
		net.ParseIP("1.1.1.3"),
	}

	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			tx.AddResolvedIP(ips[i%len(ips)], EvDNSAnswer)
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			tx.MarkObservedConn(ips[i%len(ips)], true)
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			_ = tx.ResolvedIPCount()
		}
	}()

	wg.Wait()

	if got := tx.ResolvedIPCount(); got == 0 {
		t.Fatalf("expected at least one resolved IP, got %d", got)
	}
}
