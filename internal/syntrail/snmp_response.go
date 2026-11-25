package syntrail

// berFields reads one definite-length SNMP element at a time. All views
// borrow the packet buffer only for the duration of recognition.
type berFields []byte

func (b *berFields) take(tag byte) (berFields, bool) {
	p := *b
	if len(p) < 2 || p[0] != tag {
		return nil, false
	}
	n, offset := int(p[1]), 2
	if n >= 128 {
		width := n & 127
		if width == 0 || width == 127 || width > len(p)-offset {
			return nil, false
		}
		n = 0
		for _, part := range p[offset : offset+width] {
			// The whole datagram bounds every possible content length.
			if n > len(p)/256 {
				return nil, false
			}
			n = n*256 + int(part)
		}
		offset += width
	}
	if n > len(p)-offset {
		return nil, false
	}
	value := p[offset : offset+n]
	*b = p[offset+n:]
	return value, true
}

func (b *berFields) integer() (int32, bool) {
	v, ok := b.take(2)
	if !ok || len(v) == 0 || len(v) > 4 {
		return 0, false
	}
	n := int32(int8(v[0]))
	for _, x := range v[1:] {
		n = n<<8 | int32(x)
	}
	return n, true
}

// isSNMPResponse recognizes a complete plaintext Response-PDU. It never
// retains the community, security parameters, OIDs, or returned values.
func isSNMPResponse(payload []byte) bool {
	wire := berFields(payload)
	msg, ok := wire.take(0x30)
	if !ok || len(wire) != 0 {
		return false
	}
	version, ok := msg.integer()
	if !ok {
		return false
	}
	switch version {
	case 0, 1:
		if _, ok = msg.take(4); !ok {
			return false
		}
	case 3:
		header, ok := msg.take(0x30)
		if !ok {
			return false
		}
		id, ok := header.integer()
		if !ok || id < 0 {
			return false
		}
		size, ok := header.integer()
		if !ok || size < 484 {
			return false
		}
		flags, ok := header.take(4)
		if !ok || len(flags) != 1 || flags[0]&2 != 0 {
			return false
		}
		model, ok := header.integer()
		if !ok || model <= 0 || len(header) != 0 {
			return false
		}
		if _, ok = msg.take(4); !ok {
			return false
		}
		scoped, ok := msg.take(0x30)
		if !ok || len(msg) != 0 {
			return false
		}
		// Skip contextEngineID and contextName.
		if _, ok = scoped.take(4); !ok {
			return false
		}
		if _, ok = scoped.take(4); !ok {
			return false
		}
		msg = scoped
	default:
		return false
	}
	pdu, ok := msg.take(0xa2)
	if !ok || len(msg) != 0 {
		return false
	}
	// The request ID is present even for a response-only capture.
	if _, ok = pdu.integer(); !ok {
		return false
	}
	status, ok := pdu.integer()
	if !ok || status < 0 || status > 18 || version == 0 && status > 5 {
		return false
	}
	idx, ok := pdu.integer()
	if !ok || idx < 0 {
		return false
	}
	bindings, ok := pdu.take(0x30)
	if !ok || len(pdu) != 0 {
		return false
	}
	for len(bindings) > 0 {
		binding, ok := bindings.take(0x30)
		if !ok {
			return false
		}
		name, ok := binding.take(6)
		if !ok || !validOID(name) || len(binding) == 0 {
			return false
		}
		tag := binding[0]
		value, ok := binding.take(tag)
		if !ok || len(binding) != 0 || !validBindingValue(tag, value, version) {
			return false
		}
	}
	return true
}

func validOID(v []byte) bool {
	if len(v) == 0 || v[len(v)-1]&0x80 != 0 {
		return false
	}
	start := true
	for _, b := range v {
		if start && b == 0x80 {
			return false
		}
		start = b&0x80 == 0
	}
	return true
}

func validBindingValue(tag byte, v []byte, version int32) bool {
	switch tag {
	case 2:
		return len(v) > 0 && len(v) <= 4
	case 4, 0x44:
		return true // string or opaque
	case 5:
		return len(v) == 0
	case 6:
		return validOID(v)
	case 0x40:
		return len(v) == 4 // IPv4
	case 0x41, 0x42, 0x43:
		return unsignedFits(v, 4)
	case 0x46:
		return version != 0 && unsignedFits(v, 8)
	case 0x80, 0x81, 0x82:
		return version != 0 && len(v) == 0
	default:
		return false
	}
}

func unsignedFits(v []byte, width int) bool {
	return len(v) > 0 && v[0]&0x80 == 0 && (len(v) <= width || len(v) == width+1 && v[0] == 0)
}
