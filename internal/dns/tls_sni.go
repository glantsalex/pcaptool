// Copyright © 2025 Alex Glants
// All rights reserved.
// This file is part of pcaptool—the thing I built because
// “just scroll in Wireshark forever” is not a real strategy.
// Use it, tweak it, extend it—but do not pretend you wrote it.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"encoding/binary"
	"strings"
)

// extractSNIFromClientHello tries to parse a TLS ClientHello from the given
// TCP payload and extract the SNI hostname (server_name extension).
//
// It only handles the simple case where a single TLS record containing a
// full ClientHello is present in the payload. Truncated payloads or split
// records are ignored.
func extractSNIFromClientHello(payload []byte) (string, bool) {
	// Minimum TLS record header length: 5 bytes
	if len(payload) < 5 {
		return "", false
	}

	contentType := payload[0]
	if contentType != 0x16 { // Handshake
		return "", false
	}

	// record version (bytes 1-2) are ignored
	recordLen := int(binary.BigEndian.Uint16(payload[3:5]))
	if recordLen <= 0 || len(payload) < 5+recordLen {
		return "", false
	}

	handshake := payload[5:]
	if len(handshake) < 4 {
		return "", false
	}

	handshakeType := handshake[0]
	if handshakeType != 0x01 { // ClientHello
		return "", false
	}

	// Handshake length is next 3 bytes
	// We can ignore it as long as we bounds check everything manually.
	offset := 4 // skip type (1) + length (3)

	// --- ClientHello body ---

	// 2 bytes version
	if len(handshake) < offset+2 {
		return "", false
	}
	offset += 2

	// 32 bytes random
	if len(handshake) < offset+32 {
		return "", false
	}
	offset += 32

	// Session ID
	if len(handshake) < offset+1 {
		return "", false
	}
	sessionIDLen := int(handshake[offset])
	offset++
	if len(handshake) < offset+sessionIDLen {
		return "", false
	}
	offset += sessionIDLen

	// Cipher suites
	if len(handshake) < offset+2 {
		return "", false
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(handshake[offset : offset+2]))
	offset += 2
	if len(handshake) < offset+cipherSuitesLen {
		return "", false
	}
	offset += cipherSuitesLen

	// Compression methods
	if len(handshake) < offset+1 {
		return "", false
	}
	compressionMethodsLen := int(handshake[offset])
	offset++
	if len(handshake) < offset+compressionMethodsLen {
		return "", false
	}
	offset += compressionMethodsLen

	// Extensions length
	if len(handshake) < offset+2 {
		// No extensions => no SNI
		return "", false
	}
	extensionsLen := int(binary.BigEndian.Uint16(handshake[offset : offset+2]))
	offset += 2
	if len(handshake) < offset+extensionsLen {
		return "", false
	}

	extensions := handshake[offset : offset+extensionsLen]
	extOffset := 0

	for extOffset+4 <= len(extensions) {
		extType := binary.BigEndian.Uint16(extensions[extOffset : extOffset+2])
		extLen := int(binary.BigEndian.Uint16(extensions[extOffset+2 : extOffset+4]))
		extOffset += 4

		if extOffset+extLen > len(extensions) {
			break
		}

		extData := extensions[extOffset : extOffset+extLen]
		extOffset += extLen

		// 0x0000 = server_name
		if extType != 0x0000 {
			continue
		}

		// server_name extension format:
		// 2 bytes list length
		if len(extData) < 2 {
			return "", false
		}
		listLen := int(binary.BigEndian.Uint16(extData[0:2]))
		if len(extData) < 2+listLen {
			return "", false
		}
		list := extData[2 : 2+listLen]

		// list contains one or more entries:
		// 1 byte name_type, 2 bytes name_length, then name
		pos := 0
		for pos+3 <= len(list) {
			nameType := list[pos]
			nameLen := int(binary.BigEndian.Uint16(list[pos+1 : pos+3]))
			pos += 3
			if pos+nameLen > len(list) {
				return "", false
			}
			if nameType == 0 { // host_name
				sni := strings.ToLower(strings.TrimSpace(string(list[pos : pos+nameLen])))
				return sni, true
			}
			pos += nameLen
		}
		// If we get here: server_name ext exists but no host_name type.
		return "", false
	}
	return "", false
}
