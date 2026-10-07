package pcap

import (
	"io"
	"os"
)

var sharedPacketScanMagics = map[[4]byte]struct{}{
	{0xA1, 0xB2, 0xC3, 0xD4}: {}, // classic PCAP, microseconds, big endian
	{0xD4, 0xC3, 0xB2, 0xA1}: {}, // classic PCAP, microseconds, little endian
	{0xA1, 0xB2, 0x3C, 0x4D}: {}, // classic PCAP, nanoseconds, big endian
	{0x4D, 0x3C, 0xB2, 0xA1}: {}, // classic PCAP, nanoseconds, little endian
	{0x0A, 0x0D, 0x0D, 0x0A}: {}, // PCAPNG section header
}

// SupportsSharedPacketScan reports whether path has a classic PCAP or PCAPNG
// magic supported by both the connection and fleet packet readers.
func SupportsSharedPacketScan(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return false, err
	}
	_, ok := sharedPacketScanMagics[magic]
	return ok, nil
}
