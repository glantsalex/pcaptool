package syntrail

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseFleetIPv4ListValidLines(t *testing.T) {
	fleet, err := ParseFleetIPv4List(strings.NewReader("192.0.2.1\n203.0.113.9\n"))
	if err != nil {
		t.Fatalf("ParseFleetIPv4List() error = %v", err)
	}

	for _, ip := range []string{"192.0.2.1", "203.0.113.9"} {
		if !fleet.Contains(netip.MustParseAddr(ip)) {
			t.Fatalf("fleet.Contains(%s) = false, want true", ip)
		}
	}
}

func TestParseFleetIPv4ListIgnoresBlankAndCommentLines(t *testing.T) {
	input := "\n  \n# comment\n\t# indented comment\n198.51.100.4\n"
	fleet, err := ParseFleetIPv4List(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseFleetIPv4List() error = %v", err)
	}

	if len(fleet.ips) != 1 {
		t.Fatalf("len(fleet.ips) = %d, want 1", len(fleet.ips))
	}
	if !fleet.Contains(netip.MustParseAddr("198.51.100.4")) {
		t.Fatal("fleet does not contain parsed IPv4 address")
	}
}

func TestParseFleetIPv4ListDedupesDuplicateIPs(t *testing.T) {
	input := "10.0.0.1\n10.0.0.1\n 10.0.0.1 \n"
	fleet, err := ParseFleetIPv4List(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseFleetIPv4List() error = %v", err)
	}

	if len(fleet.ips) != 1 {
		t.Fatalf("len(fleet.ips) = %d, want 1", len(fleet.ips))
	}
}

func TestParseFleetIPv4ListRejectsMalformedIP(t *testing.T) {
	_, err := ParseFleetIPv4List(strings.NewReader("192.0.2.1\nnot-an-ip\n"))
	if err == nil {
		t.Fatal("ParseFleetIPv4List() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("error = %q, want line number", err.Error())
	}
	if !strings.Contains(err.Error(), "not-an-ip") {
		t.Fatalf("error = %q, want malformed value", err.Error())
	}
}

func TestParseFleetIPv4ListRejectsIPv6(t *testing.T) {
	_, err := ParseFleetIPv4List(strings.NewReader("2001:db8::1\n"))
	if err == nil {
		t.Fatal("ParseFleetIPv4List() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "line 1") {
		t.Fatalf("error = %q, want line number", err.Error())
	}
	if !strings.Contains(err.Error(), "expected IPv4") {
		t.Fatalf("error = %q, want IPv4 rejection context", err.Error())
	}
}

func TestLoadFleetIPv4FileWrapsPathForParseErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fleet.txt")
	if err := os.WriteFile(path, []byte("192.0.2.1\nbad\n"), 0o600); err != nil {
		t.Fatalf("write test fleet file: %v", err)
	}

	_, err := LoadFleetIPv4File(path)
	if err == nil {
		t.Fatal("LoadFleetIPv4File() error = nil, want error")
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("error = %q, want path %q", err.Error(), path)
	}
	if !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("error = %q, want parse line number", err.Error())
	}
}

func TestLoadFleetIPv4FileWrapsPathForOpenErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.txt")
	_, err := LoadFleetIPv4File(path)
	if err == nil {
		t.Fatal("LoadFleetIPv4File() error = nil, want error")
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("error = %q, want path %q", err.Error(), path)
	}
}

func TestFleetSetContains(t *testing.T) {
	fleet, err := ParseFleetIPv4List(strings.NewReader("192.0.2.55\n"))
	if err != nil {
		t.Fatalf("ParseFleetIPv4List() error = %v", err)
	}

	tests := []struct {
		name string
		ip   netip.Addr
		want bool
	}{
		{name: "present IPv4", ip: netip.MustParseAddr("192.0.2.55"), want: true},
		{name: "absent IPv4", ip: netip.MustParseAddr("192.0.2.56"), want: false},
		{name: "IPv6", ip: netip.MustParseAddr("2001:db8::1"), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := fleet.Contains(tt.ip); got != tt.want {
				t.Fatalf("fleet.Contains(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestIsLocalIPv4(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{name: "10/8 lower", ip: "10.0.0.1", want: true},
		{name: "10/8 upper", ip: "10.255.255.255", want: true},
		{name: "172.16/12 lower", ip: "172.16.0.0", want: true},
		{name: "172.16/12 upper", ip: "172.31.255.255", want: true},
		{name: "192.168/16 lower", ip: "192.168.0.0", want: true},
		{name: "192.168/16 upper", ip: "192.168.255.255", want: true},
		{name: "100.64/10 lower", ip: "100.64.0.0", want: true},
		{name: "100.64/10 upper", ip: "100.127.255.255", want: true},
		{name: "172 below range", ip: "172.15.255.255", want: false},
		{name: "172 above range", ip: "172.32.0.0", want: false},
		{name: "100 below CGNAT", ip: "100.63.255.255", want: false},
		{name: "100 above CGNAT", ip: "100.128.0.0", want: false},
		{name: "public IPv4", ip: "8.8.8.8", want: false},
		{name: "IPv6", ip: "2001:db8::1", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isLocalIPv4(netip.MustParseAddr(tt.ip)); got != tt.want {
				t.Fatalf("isLocalIPv4(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}
