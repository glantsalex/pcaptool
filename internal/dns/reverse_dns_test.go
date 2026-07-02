package dns

import (
	"bytes"
	"context"
	"errors"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCompleteTopologyWithReverseDNSClassificationAndCandidateFiltering(t *testing.T) {
	entries := []TopologyEntry{
		{DestinationIP: "8.8.8.8", DNSName: "", DNSSource: "mid-session"},
		{DestinationIP: " 8.8.8.8 ", DNSName: "NONE", DNSSource: "NO ATTRIBUTION"},
		{DestinationIP: "8.8.8.8", DNSName: "existing.example", DNSSource: "dns+synack"},
		{DestinationIP: "1.1.1.1", DNSName: "[no-dns-attribution]", DNSSource: ""},
		{DestinationIP: "52.59.148.163", DNSName: "no dns attribution", DNSSource: "none"},
		{DestinationIP: "208.67.222.222", DNSName: "", DNSSource: "mid-session"},
		{DestinationIP: "4.2.2.2", DNSName: "", DNSSource: "mid-session"},
		{DestinationIP: "8.8.4.4", DNSName: "", DNSSource: "mid-session"},
		{DestinationIP: "10.0.0.1", DNSName: "", DNSSource: "mid-session"},
		{DestinationIP: "2001:4860:4860::8888", DNSName: "", DNSSource: "mid-session"},
		{DestinationIP: "8.8.8.8", DNSName: "unknown", DNSSource: "mid-session"},
		{DestinationIP: "8.8.8.8", DNSName: "", DNSSource: "csv+mid"},
		{DestinationIP: "not-an-ip", DNSName: "", DNSSource: "mid-session"},
	}

	ptrByIP := map[string][]string{
		"8.8.8.8":        {"B.Example.COM.", "a.example.com", "b.example.com."},
		"1.1.1.1":        {"one.example.com."},
		"52.59.148.163":  {"ec2-52-59-148-163.eu-central-1.compute.amazonaws.com."},
		"208.67.222.222": {"z.example.com.", "y.example.com."},
		"4.2.2.2":        {"ec2-52-59-148-163.eu-central-1.compute.amazonaws.com."},
		"8.8.4.4":        {"router.local.", "4.8.8.8.in-addr.arpa."},
	}
	forwardByName := map[string][]string{
		"a.example.com": {"1.2.3.4"},
		"b.example.com": {"2001:db8::1", "8.8.8.8", "8.8.8.8"},
		"y.example.com": {"1.2.3.4"},
		"z.example.com": {"5.6.7.8"},
	}
	var mu sync.Mutex
	addrCalls := make(map[string]int)
	hostCalls := make(map[string]int)
	resolver := &ReverseResolver{
		LookupAddr: func(_ context.Context, ip string) ([]string, error) {
			mu.Lock()
			addrCalls[ip]++
			mu.Unlock()
			return ptrByIP[ip], nil
		},
		LookupHost: func(_ context.Context, name string) ([]string, error) {
			mu.Lock()
			hostCalls[name]++
			mu.Unlock()
			if name == "one.example.com" {
				return nil, errors.New("forward unavailable")
			}
			return forwardByName[name], nil
		},
	}
	var progressMu sync.Mutex
	var progressCalls [][2]int

	got, records, err := CompleteTopologyWithReverseDNS(context.Background(), entries, resolver, ReverseDNSLookupOptions{
		Workers: 3,
		Progress: func(processed, total int) {
			progressMu.Lock()
			progressCalls = append(progressCalls, [2]int{processed, total})
			progressMu.Unlock()
		},
	})
	if err != nil {
		t.Fatalf("CompleteTopologyWithReverseDNS() error = %v", err)
	}
	if reflect.DeepEqual(got, entries) {
		t.Fatal("completed topology was not changed")
	}
	if entries[0].DNSName != "" {
		t.Fatalf("input topology mutated: %#v", entries[0])
	}

	if got[0].DNSName != "b.example.com" || got[0].DNSSource != "ptr+fcrdns+matrix" {
		t.Fatalf("FCRDNS row = %#v", got[0])
	}
	if got[1].DNSName != "b.example.com" || got[1].DNSSource != "ptr+fcrdns+matrix" {
		t.Fatalf("same-IP placeholder row = %#v", got[1])
	}
	if got[2] != entries[2] || got[10] != entries[10] || got[11] != entries[11] {
		t.Fatalf("attributed or non-placeholder rows were overwritten: %#v %#v %#v", got[2], got[10], got[11])
	}
	if got[3].DNSName != "one.example.com" || got[3].DNSSource != "ptr+matrix" {
		t.Fatalf("raw PTR row = %#v", got[3])
	}
	if got[4].DNSName != "ec2.eu-central-1.compute.amazonaws.com" || got[4].DNSSource != "ptr-normalized+matrix" {
		t.Fatalf("normalized PTR row = %#v", got[4])
	}
	for _, i := range []int{5, 6, 7, 8, 9, 12} {
		if got[i].DNSName != entries[i].DNSName || got[i].DNSSource != entries[i].DNSSource {
			t.Fatalf("row %d unexpectedly completed: %#v", i, got[i])
		}
	}

	wantIPs := []string{"1.1.1.1", "208.67.222.222", "4.2.2.2", "52.59.148.163", "8.8.4.4", "8.8.8.8"}
	if len(records) != len(wantIPs) {
		t.Fatalf("record count = %d, want %d: %#v", len(records), len(wantIPs), records)
	}
	statuses := make(map[string]string, len(records))
	recordByIP := make(map[string]ReverseDNSLookupRecord, len(records))
	for i, record := range records {
		if record.IP != wantIPs[i] {
			t.Fatalf("record %d IP = %q, want %q", i, record.IP, wantIPs[i])
		}
		statuses[record.IP] = record.Status
		recordByIP[record.IP] = record
	}
	wantStatuses := map[string]string{
		"1.1.1.1": "used_raw", "208.67.222.222": "ambiguous", "4.2.2.2": "skipped_noise",
		"8.8.4.4": "skipped_noise", "8.8.8.8": "used_fcrdns", "52.59.148.163": "used_normalized",
	}
	if !reflect.DeepEqual(statuses, wantStatuses) {
		t.Fatalf("statuses = %#v, want %#v", statuses, wantStatuses)
	}
	if record := recordByIP["8.8.8.8"]; record.RawPTR != "a.example.com;b.example.com" || record.ForwardIPs != "1.2.3.4;8.8.8.8" || record.Reason != "forward_confirmed" {
		t.Fatalf("canonical FCRDNS audit record = %#v", record)
	}
	if record := recordByIP["1.1.1.1"]; record.Reason != "valid_ptr" || !strings.Contains(record.Error, "forward unavailable") {
		t.Fatalf("raw fallback audit record = %#v", record)
	}
	if record := recordByIP["52.59.148.163"]; record.Reason != "aws_ec2_ip_encoded" {
		t.Fatalf("AWS normalized audit record = %#v", record)
	}
	if record := recordByIP["4.2.2.2"]; record.Reason != "aws_ec2_ip_mismatch" {
		t.Fatalf("AWS mismatch audit record = %#v", record)
	}
	for _, ip := range wantIPs {
		if addrCalls[ip] != 1 {
			t.Fatalf("LookupAddr(%s) calls = %d, want 1", ip, addrCalls[ip])
		}
	}
	if _, called := hostCalls["ec2-52-59-148-163.eu-central-1.compute.amazonaws.com"]; called {
		t.Fatal("matching AWS normalization unexpectedly used forward lookup")
	}
	if got := len(progressCalls); got != len(wantIPs) {
		t.Fatalf("progress calls = %d, want %d", got, len(wantIPs))
	}
	if last := progressCalls[len(progressCalls)-1]; last != [2]int{len(wantIPs), len(wantIPs)} {
		t.Fatalf("last progress = %#v", last)
	}
}

func TestCompleteTopologyWithReverseDNSLookupOutcomesAreNonFatal(t *testing.T) {
	entries := []TopologyEntry{
		{DestinationIP: "8.8.8.8", DNSSource: "mid-session"},
		{DestinationIP: "8.8.4.4", DNSSource: "mid-session"},
		{DestinationIP: "1.1.1.1", DNSSource: "mid-session"},
	}
	resolver := &ReverseResolver{
		LookupAddr: func(_ context.Context, ip string) ([]string, error) {
			switch ip {
			case "8.8.8.8":
				return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
			case "8.8.4.4":
				return []string{}, nil
			default:
				return nil, errors.New("resolver unavailable")
			}
		},
		LookupHost: func(context.Context, string) ([]string, error) {
			t.Fatal("LookupHost called without PTR names")
			return nil, nil
		},
	}

	got, records, err := CompleteTopologyWithReverseDNS(context.Background(), entries, resolver, ReverseDNSLookupOptions{})
	if err != nil {
		t.Fatalf("CompleteTopologyWithReverseDNS() error = %v", err)
	}
	if !reflect.DeepEqual(got, entries) {
		t.Fatalf("failed lookups changed topology: %#v", got)
	}
	statuses := map[string]string{}
	for _, record := range records {
		statuses[record.IP] = record.Status
	}
	want := map[string]string{"1.1.1.1": "error", "8.8.4.4": "no_ptr", "8.8.8.8": "nxdomain"}
	if !reflect.DeepEqual(statuses, want) {
		t.Fatalf("statuses = %#v, want %#v", statuses, want)
	}
}

func TestCompleteTopologyWithReverseDNSRejectsGenericIPEncodedAndExactHomeARPA(t *testing.T) {
	entries := []TopologyEntry{
		{DestinationIP: "64.6.64.6", DNSSource: "mid-session"},
		{DestinationIP: "94.140.14.14", DNSSource: "mid-session"},
		{DestinationIP: "76.76.2.0", DNSSource: "mid-session"},
		{DestinationIP: "8.26.56.26", DNSSource: "mid-session"},
	}
	ptrByIP := map[string][]string{
		"64.6.64.6":    {"static-64-6-64-6-customer.example.net."},
		"94.140.14.14": {"host.94.140.14.14.example.net."},
		"76.76.2.0":    {"home.arpa."},
		// The first token contains an extra digit and must not fuzzy-match 8.
		"8.26.56.26": {"node-18-26-56-26.example.net."},
	}
	forwardByName := map[string][]string{
		"static-64-6-64-6-customer.example.net": {"64.6.64.6"},
		"host.94.140.14.14.example.net":         {"94.140.14.14"},
		"node-18-26-56-26.example.net":          {"8.26.56.26"},
	}
	hostCalls := make(map[string]int)
	resolver := &ReverseResolver{
		LookupAddr: func(_ context.Context, ip string) ([]string, error) {
			return ptrByIP[ip], nil
		},
		LookupHost: func(_ context.Context, name string) ([]string, error) {
			hostCalls[name]++
			return forwardByName[name], nil
		},
	}

	got, records, err := CompleteTopologyWithReverseDNS(context.Background(), entries, resolver, ReverseDNSLookupOptions{Workers: 1})
	if err != nil {
		t.Fatalf("CompleteTopologyWithReverseDNS() error = %v", err)
	}
	for _, i := range []int{0, 1, 2} {
		if got[i].DNSName != "" || got[i].DNSSource != "mid-session" {
			t.Fatalf("encoded/local row %d unexpectedly completed: %#v", i, got[i])
		}
	}
	if got[3].DNSName != "node-18-26-56-26.example.net" || got[3].DNSSource != "ptr+fcrdns+matrix" {
		t.Fatalf("non-matching numeric substring row = %#v", got[3])
	}
	if hostCalls["static-64-6-64-6-customer.example.net"] != 0 || hostCalls["host.94.140.14.14.example.net"] != 0 {
		t.Fatalf("IP-encoded PTR names reached forward lookup: %#v", hostCalls)
	}
	if hostCalls["node-18-26-56-26.example.net"] != 1 {
		t.Fatalf("non-matching PTR forward calls = %d, want 1", hostCalls["node-18-26-56-26.example.net"])
	}

	recordByIP := make(map[string]ReverseDNSLookupRecord, len(records))
	for _, record := range records {
		recordByIP[record.IP] = record
	}
	for _, ip := range []string{"64.6.64.6", "94.140.14.14"} {
		record := recordByIP[ip]
		if record.Status != "skipped_noise" || record.Reason != "noisy_ip_encoded" {
			t.Fatalf("encoded PTR record for %s = %#v", ip, record)
		}
	}
	if record := recordByIP["76.76.2.0"]; record.Status != "skipped_noise" || record.Reason != "invalid_name" {
		t.Fatalf("exact home.arpa record = %#v", record)
	}
}

func TestCompleteTopologyWithReverseDNSParentCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	resolver := &ReverseResolver{
		LookupAddr: func(ctx context.Context, _ string) ([]string, error) {
			cancel()
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}

	_, _, err := CompleteTopologyWithReverseDNS(ctx, []TopologyEntry{{
		DestinationIP: "8.8.8.8",
		DNSSource:     "mid-session",
	}}, resolver, ReverseDNSLookupOptions{Workers: 1, Timeout: time.Second})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestCompleteTopologyWithReverseDNSPerIPTimeoutIsNonFatal(t *testing.T) {
	resolver := &ReverseResolver{
		LookupAddr: func(ctx context.Context, _ string) ([]string, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}

	got, records, err := CompleteTopologyWithReverseDNS(context.Background(), []TopologyEntry{{
		DestinationIP: "8.8.8.8",
		DNSSource:     "mid-session",
	}}, resolver, ReverseDNSLookupOptions{Workers: 1, Timeout: time.Millisecond})
	if err != nil {
		t.Fatalf("per-IP timeout returned operation error: %v", err)
	}
	if len(records) != 1 || records[0].Status != "error" || records[0].Reason != "lookup_error" {
		t.Fatalf("timeout records = %#v", records)
	}
	if got[0].DNSName != "" || got[0].DNSSource != "mid-session" {
		t.Fatalf("timeout changed topology: %#v", got[0])
	}
}

func TestWriteReverseDNSLookupCSVHeaderSortingAndValues(t *testing.T) {
	records := []ReverseDNSLookupRecord{
		{IP: "8.8.8.8", Status: "used_raw", RawPTR: "b.example;a.example;b.example.", NormalizedName: "a.example", Source: "ptr+matrix", Reason: "single, usable", ForwardIPs: "8.8.8.8;1.1.1.1;8.8.8.8", Error: "forward failed"},
		{IP: "1.1.1.1", Status: "used_fcrdns", RawPTR: "one.example", NormalizedName: "one.example", Source: "ptr+fcrdns+matrix", Reason: "confirmed", ForwardConfirmed: true, ForwardIPs: "1.1.1.1"},
	}
	var first bytes.Buffer
	if err := WriteReverseDNSLookupCSV(&first, records); err != nil {
		t.Fatalf("WriteReverseDNSLookupCSV() error = %v", err)
	}
	var second bytes.Buffer
	if err := WriteReverseDNSLookupCSV(&second, records); err != nil {
		t.Fatalf("second WriteReverseDNSLookupCSV() error = %v", err)
	}
	if first.String() != second.String() {
		t.Fatal("CSV output is not deterministic")
	}
	wantPrefix := "ip,status,raw_ptr,normalized_name,source,reason,forward_confirmed,forward_ips,error\n" +
		"1.1.1.1,used_fcrdns,one.example,one.example,ptr+fcrdns+matrix,confirmed,true,1.1.1.1,\n"
	if !strings.HasPrefix(first.String(), wantPrefix) {
		t.Fatalf("CSV prefix = %q, want %q", first.String(), wantPrefix)
	}
	if !strings.Contains(first.String(), `"single, usable"`) {
		t.Fatalf("CSV did not escape comma-containing reason: %q", first.String())
	}
	if !strings.Contains(first.String(), "a.example;b.example") || !strings.Contains(first.String(), "1.1.1.1;8.8.8.8") {
		t.Fatalf("CSV did not sort/dedupe multi-value fields: %q", first.String())
	}
}

func TestWriteReverseDNSLookupCSVEmptyIsHeaderOnly(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteReverseDNSLookupCSV(&buf, nil); err != nil {
		t.Fatalf("WriteReverseDNSLookupCSV() error = %v", err)
	}
	want := "ip,status,raw_ptr,normalized_name,source,reason,forward_confirmed,forward_ips,error\n"
	if buf.String() != want {
		t.Fatalf("header-only CSV = %q, want %q", buf.String(), want)
	}
}
