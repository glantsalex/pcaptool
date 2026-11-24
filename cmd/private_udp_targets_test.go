package cmd

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/aglants/pcaptool/internal/direction"
	"github.com/aglants/pcaptool/internal/syntrail"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestDailyPrivateUDPTargets(t *testing.T) {
	const a, b, c, manager = "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.61.8.71"
	// Plaintext v2c response with an empty variable-binding list.
	response, err := hex.DecodeString("3013020101040178a20b0201010201000201003000")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	fleet := filepath.Join(t.TempDir(), "fleet.txt")
	if err := os.WriteFile(fleet, []byte(a+"\n"+b+"\n"+c+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ts := time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC)
	packet := func(src, dst string, sp, dp uint16, p []byte) timestampedPacket {
		return timestampedPacket{ts: ts, data: buildUDPPacketWithPayload(t, src, dst, sp, dp, p)}
	}
	writePacketsToPCAP(t, filepath.Join(dir, "early.pcap"), []timestampedPacket{
		// UDP/1194 returns precede their matching client packets in another file.
		packet(a, manager, 1194, 49153, nil),
		packet(b, manager, 1194, 49154, nil), // same client port, wrong fleet peer
		packet(a, manager, 1194, 49155, nil), // another source port also uses this listener
		packet(a, manager, 1194, 49156, nil), // reverse UDP/161 cannot match UDP/1194
		packet(a, manager, 161, 49157, nil),  // reverse UDP/1194 cannot match UDP/161
		packet(a, manager, 1194, 49157, nil),
		packet(a, manager, 1194, 1194, nil),      // symmetric port, retain listener
		packet(a, manager, 161, 45000, nil),      // inconclusive, later matched exactly
		packet(b, manager, 161, 45001, response), // only a response is captured
		packet(b, manager, 161, 45001, response),
		packet(b, manager, 161, 162, response), // notification port takes precedence
		packet(a, manager, 161, 45003, nil),    // unmatched, ordinary listener
		packet(b, manager, 161, 45000, nil),    // port reused across devices
		packet(a, manager, 161, 45004, nil),    // shared listener with other source port
		packet(c, manager, 161, 162, response), // never promote UDP/162 alone to a target
	})
	writePacketsToPCAP(t, filepath.Join(dir, "late.pcap"), []timestampedPacket{
		packet(manager, a, 49153, 1194, nil), packet(manager, a, 49154, 1194, nil),
		packet(manager, a, 49155, 1194, nil), packet(manager, a, 49156, 161, nil),
		packet(manager, a, 49157, 1194, nil), packet(a, manager, 32100, 49155, nil),
		packet(manager, a, 1194, 1194, nil),
		packet(b, manager, 48200, 1194, nil), packet(b, manager, 48201, 1194, nil),
		packet(manager, b, 1194, 48200, nil),
		packet(manager, a, 45000, 161, nil), packet(manager, a, 45004, 161, nil),
		packet(a, manager, 22222, 45004, nil), packet(manager, a, 45006, 161, nil),
		packet(a, manager, 161, 45006, nil),
	})
	var previous []byte
	for _, workers := range []int{0, 1, 4} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) {
			opts := DefaultDNSExtractOptions()
			opts.ReadDir, opts.NetID, opts.OutputRoot, opts.Fleet = dir, "daily", t.TempDir(), fleet
			opts.DisableSNI, opts.FleetScanWorkers = true, workers
			if err := executeDNSExtract(context.Background(), opts); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(filepath.Join(findSingleRunDir(t, opts.OutputRoot, opts.NetID), privateNonFleetEndpointsFilename))
			if err != nil {
				t.Fatal(err)
			}
			known, err := direction.Decode(raw)
			if err != nil {
				t.Fatal(err)
			}
			if rules := directionRules(known); len(rules) != 0 {
				t.Fatalf("daily-only evidence learned: %v", rules)
			}
			var got syntrail.PrivateNonFleetEndpointsDocument
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatal(err)
			}
			if len(got.Endpoints) != 1 || got.Endpoints[0].IP != manager {
				t.Fatalf("unexpected endpoints %+v", got.Endpoints)
			}
			counts := func(items []syntrail.TransportBehavior) map[uint16]int {
				out := map[uint16]int{}
				for _, v := range items {
					if v.Protocol != "udp" || v.Evidence != "" {
						t.Fatalf("unexpected behavior %+v", v)
					}
					out[v.Port] = v.FleetDevicesCount
				}
				return out
			}
			if v := counts(got.Endpoints[0].Probe.Targets); !reflect.DeepEqual(v, map[uint16]int{161: 2}) {
				t.Fatalf("targets %v", v)
			}
			if v := counts(got.Endpoints[0].Server.Listeners); !reflect.DeepEqual(v, map[uint16]int{162: 2, 1194: 2, 45000: 1, 45003: 1, 45004: 1, 49154: 1, 49155: 1, 49156: 1, 49157: 1}) {
				t.Fatalf("listeners %v", v)
			}
			if previous != nil && !bytes.Equal(raw, previous) {
				t.Fatal("outputs differ across collection modes")
			}
			previous = raw
		})
	}
}
