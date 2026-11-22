package dns

import (
	"github.com/google/gopacket/layers"
	"net"
	"slices"
)

// Inline IPv4 covers the daily collection path. The cold sidecar owns other
// address bytes, with the original representation preserved for byte-wise ties.
type wireEndpoints struct {
	issuer, resolver         [4]byte
	issuerKind, resolverKind endpointKind
	wide                     *wideEndpoints
}

type wideEndpoints struct{ issuer, resolver net.IP }
type endpointKind uint8

const (
	noEndpoint endpointKind = iota
	ipv4Endpoint
	mappedEndpoint
	wideEndpoint
)

func packEndpoint(ip net.IP) ([4]byte, endpointKind) {
	if v := ip.To4(); v != nil {
		if len(ip) == net.IPv4len {
			return [4]byte(v), ipv4Endpoint
		}
		return [4]byte(v), mappedEndpoint
	}
	if ip == nil {
		return [4]byte{}, noEndpoint
	}
	return [4]byte{}, wideEndpoint
}

func makeEndpoints(issuer, resolver net.IP) wireEndpoints {
	var e wireEndpoints
	e.issuer, e.issuerKind = packEndpoint(issuer)
	if e.issuerKind == wideEndpoint {
		e.wide = &wideEndpoints{issuer: slices.Clone(issuer)}
	}
	e.setResolver(resolver)
	return e
}

func (e *wireEndpoints) setResolver(ip net.IP) {
	e.resolver, e.resolverKind = packEndpoint(ip)
	if e.resolverKind == wideEndpoint {
		if e.wide == nil {
			e.wide = new(wideEndpoints)
		}
		e.wide.resolver = slices.Clone(ip)
	} else if e.issuerKind != wideEndpoint {
		e.wide = nil
	} else {
		e.wide.resolver = nil
	}
}

func unpackIPv4(addr *[4]byte, kind endpointKind) net.IP {
	switch kind {
	case ipv4Endpoint:
		return addr[:]
	case mappedEndpoint:
		return net.IPv4(addr[0], addr[1], addr[2], addr[3])
	default:
		return nil
	}
}

func (e *wireEndpoints) issuerIP() net.IP {
	if e.issuerKind == wideEndpoint {
		return e.wide.issuer
	}
	return unpackIPv4(&e.issuer, e.issuerKind)
}

func (e *wireEndpoints) resolverIP() net.IP {
	if e.resolverKind == wideEndpoint {
		return e.wide.resolver
	}
	return unpackIPv4(&e.resolver, e.resolverKind)
}

type wireProtocol uint8

const (
	wireTCP wireProtocol = wireProtocol(layers.IPProtocolTCP)
	wireUDP wireProtocol = wireProtocol(layers.IPProtocolUDP)
)

func protocolNumber(p L4Proto) wireProtocol {
	switch p {
	case L4ProtoTCP:
		return wireTCP
	case L4ProtoUDP:
		return wireUDP
	default:
		return 0
	}
}

func (p wireProtocol) protocol() L4Proto {
	switch p {
	case wireTCP:
		return L4ProtoTCP
	case wireUDP:
		return L4ProtoUDP
	default:
		return L4ProtoUnknown
	}
}
