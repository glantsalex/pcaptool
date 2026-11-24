package syntrail

import (
	"net/netip"
	"testing"
)

func TestPrivateUDPReconciliationRespectsTimedFleetIdentity(t *testing.T) {
	manager, device := netip.MustParseAddr("10.61.8.71"), netip.MustParseAddr("10.0.0.1")
	ports := &pollPorts{ports: map[uint16]struct{}{45000: {}}}
	request := Record{SrcIP: manager, DstIP: device, DstPort: 161, Protocol: ProtocolUDP, FleetIdentity: "imsi-a", pollPorts: ports}
	oldReturn := Record{SrcIP: device, DstIP: manager, DstPort: 45000, Protocol: ProtocolUDP, FleetIdentity: "imsi-a", returnEvidence: unverifiedReturn}
	newReturn := oldReturn
	newReturn.FleetIdentity = "imsi-b"
	unknown := oldReturn
	unknown.FleetIdentity = ""
	unknown.returnEvidence = decodedResponse
	listeners, targets := PrivateEndpointBehaviors([]Record{oldReturn, newReturn, unknown}, []Record{request})
	doc := buildPrivateNonFleetEndpointsDocumentWithIMSI(listeners, targets, true)
	if len(doc.Endpoints) != 1 {
		t.Fatalf("endpoints %+v", doc.Endpoints)
	}
	e := doc.Endpoints[0]
	if len(e.Server.Listeners) != 1 || e.Server.Listeners[0].FleetDevicesCount != 1 || e.Server.Listeners[0].Port != 45000 {
		t.Fatalf("listeners %+v", e.Server)
	}
	if len(e.Probe.Targets) != 1 || e.Probe.Targets[0].FleetDevicesCount != 1 || e.Probe.Targets[0].UnresolvedFleetIPsCount != 1 {
		t.Fatalf("targets %+v", e.Probe)
	}
}
