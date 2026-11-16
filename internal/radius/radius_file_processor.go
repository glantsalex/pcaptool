package radius

import (
	"bufio"
	"context"
	"crypto/sha1"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

// IMSI detection: 14–16 digits is common, sometimes 15.
var imsiDigitsRe = regexp.MustCompile(`^[0-9]{14,16}$`)

func processRadiusFile(
	ctx context.Context,
	path string,
	collector *radiusCollector,
) error {

	var src *gopacket.PacketSource

	fileCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	//  buffer locally to reduce lock churn, then flush to shared collector
	local := make([]radMsg, 0, 256)

	var captureEnd time.Time

	r := bufio.NewReader(f)
	magic, _ := r.Peek(4)

	if len(magic) == 4 && magic[0] == 0x0A && magic[1] == 0x0D && magic[2] == 0x0D && magic[3] == 0x0A {
		// pcapng
		ngr, e := pcapgo.NewNgReader(r, pcapgo.DefaultNgReaderOptions)
		if e != nil {
			return e
		}
		src = gopacket.NewPacketSource(ngr, ngr.LinkType())
	} else {
		// classic pcap
		handle, e := pcap.OpenOffline(path)
		if e != nil {
			return e
		}
		defer handle.Close()
		src = gopacket.NewPacketSource(handle, handle.LinkType())
	}

	for {
		if err := fileCtx.Err(); err != nil {
			return err
		}
		pkt, err := src.NextPacket()
		if err == io.EOF {
			if err := fileCtx.Err(); err != nil {
				return err
			}
			collector.AddBatch(local)
			collector.ObserveCaptureEnd(captureEnd)
			return nil
		}
		if err != nil {
			return fmt.Errorf("read RADIUS capture: %w", err)
		}
		if ts := pkt.Metadata().Timestamp; ts.After(captureEnd) {
			captureEnd = ts
		}

		netL := pkt.NetworkLayer()
		transL := pkt.TransportLayer()
		if netL == nil || transL == nil {
			continue
		}
		udp, ok := transL.(*layers.UDP)
		if !ok || !(isRadiusPort(udp.SrcPort) || isRadiusPort(udp.DstPort)) {
			continue
		}

		var rad layers.RADIUS
		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeRADIUS, &rad)
		decoded := []gopacket.LayerType{}
		if err := parser.DecodeLayers(udp.Payload, &decoded); err != nil {
			continue
		}
		if rad.Code != layers.RADIUSCodeAccountingRequest {
			continue
		}

		ip, imsi := extractIPAndIMSI(&rad)
		if ip == "" || imsi == "" {
			continue
		}

		if net.ParseIP(ip) == nil {
			continue
		}

		status, sid, sessTimeSec, hasSessionTime, ok := extractStatusAndSessionID(&rad)
		if !ok {
			continue
		}

		pktTsMs := pkt.Metadata().Timestamp.UTC().UnixMilli()

		local = append(local, radMsg{tsMs: pktTsMs, imsi: imsi, ip: ip, sid: sid,
			status: mapAcctStatusToRadStatus(status), sessTimeSec: sessTimeSec,
			hasSessionTime: hasSessionTime, dedupKey: rawDedupKey(&rad, netL, udp)})
		if len(local) >= 256 {
			collector.AddBatch(local)
			local = local[:0]
		}
	}
}

func isRadiusPort(p layers.UDPPort) bool {
	return p == 1812 || p == 1813 || p == 1645 || p == 1646
}

func rawDedupKey(rad *layers.RADIUS, netL gopacket.NetworkLayer, udp *layers.UDP) string {
	nasIP := ""
	switch ip := netL.(type) {
	case *layers.IPv4:
		nasIP = ip.SrcIP.String()
	case *layers.IPv6:
		nasIP = ip.SrcIP.String()
	}
	canon := canonicalRadiusPayload(udp.Payload)
	sum := sha1.Sum(canon)
	return fmt.Sprintf("%d|%d|%s|%d|%x", int(rad.Code), int(rad.Identifier), nasIP, int(udp.SrcPort), sum[:])
}

// canonicalRadiusPayload zeroes fields that vary across paths (authenticator, Proxy-State, Acct-Delay-Time, Message-Authenticator).
func canonicalRadiusPayload(udpPayload []byte) []byte {
	if len(udpPayload) < 20 {
		return append([]byte(nil), udpPayload...)
	}
	buf := append([]byte(nil), udpPayload...)
	for i := 4; i < 20 && i < len(buf); i++ {
		buf[i] = 0
	} // zero 16B Request Authenticator
	i := 20
	for i+2 <= len(buf) {
		typ := buf[i]
		if i+1 >= len(buf) {
			break
		}
		l := int(buf[i+1])
		if l < 2 || i+l > len(buf) {
			break
		}
		if typ == 33 || typ == 41 || typ == 80 { // Proxy-State, Acct-Delay-Time, Message-Authenticator
			for j := i + 2; j < i+l; j++ {
				buf[j] = 0
			}
		}
		i += l
	}
	return buf
}
func extractStatusAndSessionID(r *layers.RADIUS) (status uint32, sid string, sessTimeSec uint32, hasSessionTime, ok bool) {
	for _, a := range r.Attributes {
		switch a.Type {
		case layers.RADIUSAttributeTypeAcctStatusType: // 40
			if len(a.Value) >= 4 {
				status = uint32(a.Value[0])<<24 | uint32(a.Value[1])<<16 | uint32(a.Value[2])<<8 | uint32(a.Value[3])
			}
		case layers.RADIUSAttributeTypeAcctSessionId: // 44
			sid = canonicalSID(string(a.Value))
		case layers.RADIUSAttributeTypeAcctSessionTime: // 46 (seconds)+
			if len(a.Value) >= 4 {
				hasSessionTime = true
				sessTimeSec = uint32(a.Value[0])<<24 | uint32(a.Value[1])<<16 | uint32(a.Value[2])<<8 | uint32(a.Value[3])
			}
		}
	}
	return status, sid, sessTimeSec, hasSessionTime, status == acctStatusStart || status == acctStatusInterim || status == acctStatusStop
}

func extractIPAndIMSI(r *layers.RADIUS) (ip, imsi string) {
	var userName string
	var vsaIMSI string

	for _, a := range r.Attributes {
		switch a.Type {
		case layers.RADIUSAttributeTypeFramedIPAddress:
			if len(a.Value) >= 4 {
				ip = net.IP(a.Value[:4]).String()
			}
		case layers.RADIUSAttributeTypeUserName:
			userName = string(a.Value)
		case layers.RADIUSAttributeTypeVendorSpecific:
			vendor, vtype, vdata := parseVSA(a.Value)
			// 3GPP vendor (10415), IMSI is VSA type 1
			if vendor == 10415 && vtype == 1 && len(vdata) > 0 {
				vsaIMSI = canonicalIMSI(string(vdata))
			}
		}
	}

	if vsaIMSI != "" {
		imsi = vsaIMSI
	} else {
		imsi = canonicalIMSI(userName)
	}

	return ip, imsi
}

func canonicalIMSI(s string) string {
	// Trim whitespace and NULs
	s = strings.TrimSpace(strings.Trim(s, "\x00"))

	// Strip realm if present
	if i := strings.IndexByte(s, '@'); i > 0 {
		s = s[:i]
	}

	// Keep digits only (defensive against odd separators)
	var b []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			b = append(b, c)
		}
	}
	out := string(b)

	// IMSIs are typically 15, sometimes 14/16 with MVNO quirks; enforce band.
	if imsiDigitsRe.MatchString(out) {
		return out
	}
	return ""
}

// parseVSA parses RFC2865 VSA payload: 4B Vendor-Id + 1B Vendor-Type + 1B Vendor-Length + Value...
func parseVSA(b []byte) (vendor uint32, vtype uint8, vdata []byte) {
	if len(b) < 6 {
		return 0, 0, nil
	}
	vendor = uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	vtype = b[4]
	vlen := int(b[5])
	if vlen < 2 || 4+vlen > len(b) {
		return vendor, vtype, nil
	}
	return vendor, vtype, b[6 : 4+vlen]
}

func canonicalSID(s string) string {
	// trim ASCII/Unicode spaces and trailing NULs; normalize to NFC if needed
	s = strings.TrimSpace(strings.TrimRight(s, "\x00"))
	return s
}

// tiny helper returning radStart/radInterm/radStop
func mapAcctStatusToRadStatus(v uint32) radStatus {
	switch v {
	case acctStatusStart:
		return radStart
	case acctStatusInterim:
		return radInterm
	case acctStatusStop:
		return radStop
	default:
		return radInterm
	}
}
