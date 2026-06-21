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
