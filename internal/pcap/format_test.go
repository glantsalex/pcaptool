package pcap

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSupportsSharedPacketScanRecognizesPCAPAndPCAPNGMagic(t *testing.T) {
	tests := []struct {
		name  string
		magic []byte
		want  bool
	}{
		{name: "microseconds big endian", magic: []byte{0xA1, 0xB2, 0xC3, 0xD4}, want: true},
		{name: "microseconds little endian", magic: []byte{0xD4, 0xC3, 0xB2, 0xA1}, want: true},
		{name: "nanoseconds big endian", magic: []byte{0xA1, 0xB2, 0x3C, 0x4D}, want: true},
		{name: "nanoseconds little endian", magic: []byte{0x4D, 0x3C, 0xB2, 0xA1}, want: true},
		{name: "pcapng named pcap", magic: []byte{0x0A, 0x0D, 0x0D, 0x0A}, want: true},
		{name: "unknown", magic: []byte{0x01, 0x02, 0x03, 0x04}, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "capture.pcap")
			if err := os.WriteFile(path, append(tc.magic, 0, 0, 0, 0), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := SupportsSharedPacketScan(path)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("SupportsSharedPacketScan() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSupportsSharedPacketScanReturnsErrorForMissingOrShortInput(t *testing.T) {
	short := filepath.Join(t.TempDir(), "short.pcap")
	if err := os.WriteFile(short, []byte{0xD4, 0xC3}, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(t.TempDir(), "missing.pcap"), short} {
		if got, err := SupportsSharedPacketScan(path); err == nil || got {
			t.Fatalf("SupportsSharedPacketScan(%q) = %v, %v, want false and error", path, got, err)
		}
	}
}
