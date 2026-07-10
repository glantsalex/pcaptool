package dns

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestResponseOnlyDNSAnswerDrivesTopologyAttribution(t *testing.T) {
	const (
		wantIssuer = "10.245.214.104"
		wantDst    = "23.48.23.56"
		wantName   = "cdn.samsungcloudsolution.com"
		wantSource = "dns+synack"
		wantProto  = "tcp"
		wantPort   = uint16(80)
	)

	path := filepath.Join("testdata", "response_only_dns_cdn_samsung.pcap")
	files := []string{path}
	ctx := context.Background()

	txs, _, _, err := BuildTransactionsWithSNIFromPCAPsWithDiagnostics(ctx, files, false, true)
	if err != nil {
		t.Fatalf("build DNS transactions from response-only fixture: %v", err)
	}

	var sawResponseOnlyAnswer bool
	for _, tx := range txs {
		if tx == nil {
			continue
		}
		t.Logf(
			"tx issuer=%s name=%q resolver=%s resolved=%v name_evidence=%s ip_evidence=%v",
			tx.IssuerIP,
			tx.DNSName,
			tx.ResolverIP,
			tx.ResolvedIPs,
			EvidenceString(tx.NameEvidence),
			tx.ResolvedIPEvidence,
		)
		if tx.IssuerIP.String() == wantIssuer &&
			tx.DNSName == wantName &&
			responseOnlyContainsIPString(tx.ResolvedIPs, wantDst) &&
			tx.NameEvidence == EvDNSAnswer &&
			tx.ResolvedIPEvidence[wantDst] == EvDNSAnswer {
			sawResponseOnlyAnswer = true
		}
	}
	if !sawResponseOnlyAnswer {
		t.Fatalf("DNS transactions did not contain response-only %s A %s with DNS-answer evidence", wantName, wantDst)
	}

	edges, _, err := AttachConnectionsAndCollectEdgesFromPCAPs(
		ctx,
		files,
		txs,
		true,
		false,
		nil,
		false,
		nil,
		nil,
		0,
	)
	if err != nil {
		t.Fatalf("attach connections and collect edges: %v", err)
	}
	for _, edge := range edges {
		t.Logf("edge issuer=%s dst=%s proto=%s port=%d first=%s", edge.IssuerIP, edge.DstIP, edge.Protocol, edge.Port, edge.FirstSeen.UTC().Format(time.RFC3339Nano))
	}

	opt := DefaultTopologyBuildOptions()
	opt.MaxDNSAge = 5 * time.Minute
	matrix := BuildNetworkTopologyMatrixEntriesWithOptions(txs, edges, nil, nil, opt)

	var matching []TopologyEntry
	var foundStrong bool
	for _, row := range matrix {
		if row.IssuerIP == wantIssuer &&
			row.DestinationIP == wantDst &&
			strings.EqualFold(strings.TrimSpace(row.Protocol), wantProto) &&
			row.Port == wantPort {
			matching = append(matching, row)
			if row.DNSName == wantName && row.DNSSource == wantSource {
				foundStrong = true
			}
		}
	}

	for _, row := range matching {
		t.Logf("matching matrix row: issuer=%s dst=%s dns=%q source=%q proto=%s port=%d observed=%s",
			row.IssuerIP,
			row.DestinationIP,
			row.DNSName,
			row.DNSSource,
			row.Protocol,
			row.Port,
			row.ObservedAt.UTC().Format(time.RFC3339Nano),
		)
	}
	if !foundStrong {
		t.Fatalf(
			"matrix did not contain response-only strong DNS attribution for %s -> %s %s/%d; matching rows: %+v",
			wantIssuer,
			wantDst,
			wantProto,
			wantPort,
			matching,
		)
	}
}

func responseOnlyContainsIPString(ips []net.IP, want string) bool {
	parsed := net.ParseIP(want)
	for _, ip := range ips {
		if ip != nil && ip.Equal(parsed) {
			return true
		}
	}
	return false
}
