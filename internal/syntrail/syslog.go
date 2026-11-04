package syntrail

import (
	"bytes"
	"net/netip"
	"sync"
)

type syslogEndpoint struct {
	IP   netip.Addr
	Port uint16
}

// SyslogCache retains positive endpoint qualification for one stream run.
// It never owns packet buffers. Concurrent duplicate recognition is harmless.
type SyslogCache struct {
	mu        sync.RWMutex
	endpoints map[syslogEndpoint]struct{}
}

func NewSyslogCache() *SyslogCache { return &SyslogCache{endpoints: make(map[syslogEndpoint]struct{})} }
func (c *SyslogCache) Known(ip netip.Addr, port uint16) bool {
	c.mu.RLock()
	_, ok := c.endpoints[syslogEndpoint{ip, port}]
	c.mu.RUnlock()
	return ok
}
func (c *SyslogCache) Add(ip netip.Addr, port uint16) {
	c.mu.Lock()
	c.endpoints[syslogEndpoint{ip, port}] = struct{}{}
	c.mu.Unlock()
}
func (c *SyslogCache) Qualify(ip netip.Addr, port uint16, payload []byte) bool {
	if c.Known(ip, port) {
		return true
	}
	if !RecognizeSyslog(payload) {
		return false
	}
	c.Add(ip, port)
	return true
}

// RecognizeSyslog checks a bounded header prefix, not the message body.
// A truncated body is acceptable; an incomplete qualifying header is not.
// RFC5424 and conventional RFC3164 headers are supported without allocations.
func RecognizeSyslog(p []byte) bool {
	if len(p) > 128 {
		p = p[:128]
	}
	if len(p) < 6 || p[0] != '<' {
		return false
	}
	i, pri := 1, 0
	for i < len(p) && i <= 3 && p[i] >= '0' && p[i] <= '9' {
		pri = pri*10 + int(p[i]-'0')
		i++
	}
	if i == 1 || i >= len(p) || p[i] != '>' || pri > 191 {
		return false
	}
	p = p[i+1:]
	// RFC5424: version + timestamp + hostname + application + procid + msgid
	// + start of structured data. Require terminated tokens, not a full body.
	if len(p) > 2 && p[0] == '1' && p[1] == ' ' {
		p = p[2:]
		var tok []byte
		tok, p = token(p)
		if !syslogTimestamp(tok) {
			return false
		}
		for _, limit := range []int{255, 48, 128, 32} {
			tok, p = token(p)
			if len(tok) == 0 || len(tok) > limit || !printable(tok) {
				return false
			}
		}
		return len(p) > 0 && (p[0] == '[' || p[0] == '-' && (len(p) == 1 || p[1] == ' '))
	}
	// RFC3164 timestamp is exactly "Mmm dd hh:mm:ss" (day may be space padded).
	if len(p) < 17 {
		return false
	}
	month := p[:3]
	validMonth := false
	for _, m := range []string{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"} {
		if string(month) == m {
			validMonth = true
			break
		}
	}
	if !validMonth || p[3] != ' ' || p[6] != ' ' || p[15] != ' ' {
		return false
	}
	day := p[4:6]
	if day[0] == ' ' {
		if day[1] < '1' || day[1] > '9' {
			return false
		}
	} else if !numberRange(day, 1, 31) {
		return false
	}
	if !clock(p[7:15]) {
		return false
	}
	host, rest := token(p[16:])
	if len(host) == 0 || !printable(host) || len(rest) == 0 {
		return false
	}
	// A conventional tag ending in ':' provides evidence beyond a generic date.
	end := bytes.IndexByte(rest, ':')
	return end > 0 && end <= 48 && printable(rest[:end]) && bytes.IndexByte(rest[:end], ' ') < 0
}
func token(p []byte) ([]byte, []byte) {
	i := bytes.IndexByte(p, ' ')
	if i <= 0 {
		return nil, nil
	}
	return p[:i], p[i+1:]
}
func printable(p []byte) bool {
	for _, b := range p {
		if b < 33 || b > 126 {
			return false
		}
	}
	return true
}
func numberRange(p []byte, min, max int) bool {
	n := 0
	for _, b := range p {
		if b < '0' || b > '9' {
			return false
		}
		n = n*10 + int(b-'0')
	}
	return len(p) > 0 && n >= min && n <= max
}
func clock(p []byte) bool {
	return len(p) == 8 && p[2] == ':' && p[5] == ':' && numberRange(p[:2], 0, 23) && numberRange(p[3:5], 0, 59) && numberRange(p[6:], 0, 60)
}
func syslogTimestamp(p []byte) bool {
	if bytes.Equal(p, []byte("-")) {
		return true
	}
	if len(p) < 20 || p[4] != '-' || p[7] != '-' || p[10] != 'T' || !numberRange(p[:4], 1, 9999) || !numberRange(p[5:7], 1, 12) || !numberRange(p[8:10], 1, 31) || !clock(p[11:19]) {
		return false
	}
	p = p[19:]
	if len(p) > 0 && p[0] == '.' {
		i := 1
		for i < len(p) && p[i] >= '0' && p[i] <= '9' {
			i++
		}
		if i < 2 || i > 7 {
			return false
		}
		p = p[i:]
	}
	return bytes.Equal(p, []byte("Z")) || len(p) == 6 && (p[0] == '+' || p[0] == '-') && p[3] == ':' && numberRange(p[1:3], 0, 23) && numberRange(p[4:], 0, 59)
}
