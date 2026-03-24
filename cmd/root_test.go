package cmd

import "testing"

func TestSuppressBannerFromArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{name: "empty", args: nil, want: false},
		{name: "simple flag", args: []string{"--no-banner"}, want: true},
		{name: "subcommand flag", args: []string{"dnsextract", "--no-banner"}, want: true},
		{name: "explicit true", args: []string{"--no-banner=true"}, want: true},
		{name: "explicit one", args: []string{"--no-banner=1"}, want: true},
		{name: "explicit false", args: []string{"--no-banner=false"}, want: false},
		{name: "other args", args: []string{"dnsextract", "--read-dir", "/tmp/in"}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SuppressBannerFromArgs(tt.args); got != tt.want {
				t.Fatalf("SuppressBannerFromArgs(%v) = %t, want %t", tt.args, got, tt.want)
			}
		})
	}
}
