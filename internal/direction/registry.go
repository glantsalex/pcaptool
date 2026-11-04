// Package direction defines the versioned fleet direction evidence contract.
package direction

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"time"
)

const Version = 1
const GeneratorVersion = "cumulative-v1"

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

var Identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

type Behavior struct {
	Protocol  string `json:"protocol"`
	Port      uint16 `json:"port"`
	Evidence  string `json:"evidence,omitempty"`
	FirstSeen string `json:"first_seen,omitempty"`
	LastSeen  string `json:"last_seen,omitempty"`
}
type Server struct {
	Listeners []Behavior `json:"listeners"`
}
type Probe struct {
	Targets []Behavior `json:"targets"`
}
type Endpoint struct {
	IP     string `json:"ip"`
	Server Server `json:"server"`
	Probe  Probe  `json:"probe"`
}
type Document struct {
	SchemaVersion int        `json:"schema_version"`
	AccountID     string     `json:"account_id,omitempty"`
	StreamID      string     `json:"stream_id,omitempty"`
	Endpoints     []Endpoint `json:"endpoints"`
}

// Decode checks the daily/registry envelope. Daily count fields are intentionally
// ignored: counts cannot be summed across captures or data days.
func Decode(data []byte) (Document, error) {
	var d Document
	if err := json.Unmarshal(data, &d); err != nil {
		return d, err
	}
	if d.SchemaVersion != Version || d.Endpoints == nil {
		return d, fmt.Errorf("invalid direction schema/envelope")
	}
	for _, e := range d.Endpoints {
		ip, err := netip.ParseAddr(e.IP)
		if err != nil || !Private(ip) {
			return d, fmt.Errorf("invalid private endpoint %q", e.IP)
		}
		for _, b := range append(append([]Behavior{}, e.Server.Listeners...), e.Probe.Targets...) {
			if b.Port == 0 || (b.Protocol != "tcp" && b.Protocol != "udp") {
				return d, fmt.Errorf("invalid transport at %s", e.IP)
			}
			if b.Evidence != "" && b.Evidence != "tcp_syn" && b.Evidence != "syslog" {
				return d, fmt.Errorf("unknown evidence %q", b.Evidence)
			}
			if (b.Protocol == "tcp" && b.Evidence == "syslog") || (b.Protocol == "udp" && b.Evidence == "tcp_syn") {
				return d, fmt.Errorf("evidence/transport mismatch")
			}
		}
		for _, b := range e.Probe.Targets {
			if b.Protocol != "tcp" {
				return d, fmt.Errorf("UDP probe evidence is unsupported")
			}
		}
	}
	return d, nil
}

func Private(ip netip.Addr) bool {
	return ip.Is4() && (ip.IsPrivate() || cgnat.Contains(ip))
}

// ValidateRegistry rejects malformed or unqualified persistent evidence.
func (d Document) ValidateRegistry(account, stream string) error {
	if !Identifier.MatchString(account) || !Identifier.MatchString(stream) || d.AccountID != account || d.StreamID != stream {
		return fmt.Errorf("registry identity mismatch")
	}
	for _, e := range d.Endpoints {
		for _, b := range append(append([]Behavior{}, e.Server.Listeners...), e.Probe.Targets...) {
			first, err := time.Parse("2006-01-02", b.FirstSeen)
			if err != nil {
				return fmt.Errorf("invalid first_seen")
			}
			last, err := time.Parse("2006-01-02", b.LastSeen)
			if err != nil || last.Before(first) {
				return fmt.Errorf("invalid last_seen")
			}
			if !qualified(b) {
				return fmt.Errorf("unqualified persistent evidence")
			}
		}
	}
	return nil
}
func qualified(b Behavior) bool {
	return b.Protocol == "tcp" && b.Evidence == "tcp_syn" || b.Protocol == "udp" && b.Evidence == "syslog"
}

// Merge is a monotonic union; replay and out-of-order data days are harmless.
// Legacy TCP discovery is SYN-qualified by the producer contract; legacy UDP
// observations without explicit syslog evidence are deliberately not promoted.
func Merge(old, daily Document, account, stream, day string) (Document, error) {
	if _, err := time.Parse("2006-01-02", day); err != nil {
		return Document{}, err
	}
	if err := old.ValidateRegistry(account, stream); err != nil {
		return Document{}, err
	}
	if daily.StreamID != "" && daily.StreamID != stream || daily.AccountID != "" && daily.AccountID != account {
		return Document{}, fmt.Errorf("discovery identity mismatch")
	}
	type key struct {
		ip, role, protocol string
		port               uint16
	}
	entries := map[key]Behavior{}
	add := func(d Document, observed bool) {
		for _, e := range d.Endpoints {
			for _, role := range []string{"server", "probe"} {
				list := e.Server.Listeners
				if role == "probe" {
					list = e.Probe.Targets
				}
				for _, b := range list {
					if observed && b.Protocol == "tcp" && b.Evidence == "" {
						b.Evidence = "tcp_syn"
					}
					if !qualified(b) {
						continue
					}
					if observed {
						b.FirstSeen, b.LastSeen = day, day
					}
					k := key{e.IP, role, b.Protocol, b.Port}
					if prev, ok := entries[k]; ok {
						if prev.FirstSeen < b.FirstSeen {
							b.FirstSeen = prev.FirstSeen
						}
						if prev.LastSeen > b.LastSeen {
							b.LastSeen = prev.LastSeen
						}
					}
					entries[k] = b
				}
			}
		}
	}
	add(old, false)
	add(daily, true)
	keys := make([]key, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.ip != b.ip {
			return a.ip < b.ip
		}
		if a.role != b.role {
			return a.role < b.role
		}
		if a.protocol != b.protocol {
			return a.protocol < b.protocol
		}
		return a.port < b.port
	})
	out := Document{SchemaVersion: Version, AccountID: account, StreamID: stream, Endpoints: []Endpoint{}}
	for _, k := range keys {
		if len(out.Endpoints) == 0 || out.Endpoints[len(out.Endpoints)-1].IP != k.ip {
			out.Endpoints = append(out.Endpoints, Endpoint{IP: k.ip, Server: Server{[]Behavior{}}, Probe: Probe{[]Behavior{}}})
		}
		e := &out.Endpoints[len(out.Endpoints)-1]
		if k.role == "server" {
			e.Server.Listeners = append(e.Server.Listeners, entries[k])
		} else {
			e.Probe.Targets = append(e.Probe.Targets, entries[k])
		}
	}
	return out, nil
}
