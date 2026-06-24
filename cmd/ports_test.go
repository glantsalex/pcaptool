package cmd

import (
	"strings"
	"testing"
)

func TestParseStrictPortSet(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []uint16
		wantErr string
	}{
		{name: "default", input: "21,990", want: []uint16{21, 990}},
		{name: "trims custom entries", input: " 21, 990 , 21000 ", want: []uint16{21, 990, 21000}},
		{name: "custom replacement only", input: "21000", want: []uint16{21000}},
		{name: "valid boundaries", input: "1,65535", want: []uint16{1, 65535}},
		{name: "trims entries and deduplicates", input: " 21 , 990,21 ", want: []uint16{21, 990}},
		{name: "empty", input: "", wantErr: "entry 1"},
		{name: "whitespace", input: " \t ", wantErr: "entry 1"},
		{name: "leading comma", input: ",21", wantErr: "entry 1"},
		{name: "trailing comma", input: "21,", wantErr: "entry 2"},
		{name: "double comma", input: "21,,990", wantErr: "entry 2"},
		{name: "nonnumeric", input: "21,ftp", wantErr: `entry 2 value "ftp"`},
		{name: "zero", input: "0", wantErr: `entry 1 value "0"`},
		{name: "negative", input: "-1", wantErr: `entry 1 value "-1"`},
		{name: "too large", input: "65536", wantErr: `entry 1 value "65536"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseStrictPortSet(tt.input)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("parseStrictPortSet(%q) error = %v, want containing %q", tt.input, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseStrictPortSet(%q) error: %v", tt.input, err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("parseStrictPortSet(%q) = %#v, want %v", tt.input, got, tt.want)
			}
			for _, port := range tt.want {
				if _, ok := got[port]; !ok {
					t.Fatalf("parseStrictPortSet(%q) missing port %d: %#v", tt.input, port, got)
				}
			}
		})
	}
}

func TestParseOptionalPortRangeSet(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []uint16
		wantErr string
	}{
		{name: "empty disables", input: "", want: []uint16{}},
		{name: "whitespace disables", input: " \t ", want: []uint16{}},
		{name: "single port", input: "53", want: []uint16{53}},
		{name: "inclusive range", input: "33434-33436", want: []uint16{33434, 33435, 33436}},
		{
			name:  "documented mixed example",
			input: "33434-33534,40000,45000-45100",
			want: append(
				append(portRangeForTest(33434, 33534), 40000),
				portRangeForTest(45000, 45100)...,
			),
		},
		{name: "mixed ports and ranges", input: " 53, 100-102, 65535 ", want: []uint16{53, 100, 101, 102, 65535}},
		{name: "valid boundaries", input: "1,65535", want: []uint16{1, 65535}},
		{name: "single value range", input: "443-443", want: []uint16{443}},
		{name: "overlap and duplicates", input: "100-102,101,102-103", want: []uint16{100, 101, 102, 103}},
		{name: "spaces around range separator", input: " 33434 - 33435 ", want: []uint16{33434, 33435}},
		{name: "leading comma", input: ",53", wantErr: "entry 1"},
		{name: "trailing comma", input: "53,", wantErr: "entry 2"},
		{name: "double comma", input: "53,,123", wantErr: "entry 2"},
		{name: "documented double comma", input: "33434,,33534", wantErr: "entry 2"},
		{name: "documented trailing comma", input: "33434,", wantErr: "entry 2"},
		{name: "documented leading comma", input: ",33434", wantErr: "entry 1"},
		{name: "nonnumeric port", input: "dns", wantErr: `entry 1 value "dns"`},
		{name: "documented nonnumeric port", input: "abc", wantErr: `entry 1 value "abc"`},
		{name: "nonnumeric range start", input: "dns-53", wantErr: "start"},
		{name: "nonnumeric range end", input: "53-dns", wantErr: "end"},
		{name: "documented nonnumeric range end", input: "33434-abc", wantErr: "end"},
		{name: "missing range start", input: "-53", wantErr: "start"},
		{name: "missing range end", input: "53-", wantErr: "end"},
		{name: "documented missing range start", input: "-33534", wantErr: "start"},
		{name: "documented missing range end", input: "33434-", wantErr: "end"},
		{name: "too many separators", input: "53-54-55", wantErr: "port or inclusive start-end range"},
		{name: "zero port", input: "0", wantErr: "must be 1..65535"},
		{name: "negative port", input: "-1", wantErr: "start"},
		{name: "too large port", input: "65536", wantErr: "must be 1..65535"},
		{name: "zero range start", input: "0-53", wantErr: "must be 1..65535"},
		{name: "too large range end", input: "53-65536", wantErr: "must be 1..65535"},
		{name: "reversed range", input: "33534-33434", wantErr: "range start 33534 exceeds end 33434"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseOptionalPortRangeSet(tt.input)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("parseOptionalPortRangeSet(%q) error = %v, want containing %q", tt.input, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseOptionalPortRangeSet(%q) error: %v", tt.input, err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("parseOptionalPortRangeSet(%q) = %#v, want %v", tt.input, got, tt.want)
			}
			for _, port := range tt.want {
				if _, ok := got[port]; !ok {
					t.Fatalf("parseOptionalPortRangeSet(%q) missing port %d: %#v", tt.input, port, got)
				}
			}
		})
	}
}

func portRangeForTest(start, end uint16) []uint16 {
	ports := make([]uint16, 0, int(end-start)+1)
	for port := int(start); port <= int(end); port++ {
		ports = append(ports, uint16(port))
	}
	return ports
}

func TestParsePortSetRemainsPermissive(t *testing.T) {
	got, err := parsePortSet(" ,21,, ")
	if err != nil {
		t.Fatalf("parsePortSet() error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("parsePortSet() = %#v, want only port 21", got)
	}
	if _, ok := got[21]; !ok {
		t.Fatalf("parsePortSet() = %#v, want port 21", got)
	}
}

func TestParseStrictPort(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    uint16
		wantErr string
	}{
		{name: "minimum", input: "1", want: 1},
		{name: "default", input: "30000", want: 30000},
		{name: "maximum", input: "65535", want: 65535},
		{name: "trims whitespace", input: " 40000 ", want: 40000},
		{name: "empty", input: "", wantErr: "must not be empty"},
		{name: "whitespace", input: " \t ", wantErr: "must not be empty"},
		{name: "zero", input: "0", wantErr: "must be 1..65535"},
		{name: "negative", input: "-1", wantErr: "must be 1..65535"},
		{name: "nonnumeric", input: "ftp", wantErr: "must be numeric"},
		{name: "too large", input: "65536", wantErr: "must be 1..65535"},
		{name: "multiple ports", input: "30000,40000", wantErr: "must be numeric"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseStrictPort(tt.input)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("parseStrictPort(%q) error = %v, want containing %q", tt.input, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseStrictPort(%q) error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("parseStrictPort(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}
