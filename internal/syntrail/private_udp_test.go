package syntrail

import "testing"

func TestPrivateUDPReconciliationRespectsTimedFleetIdentity(t *testing.T) {
	manager, device := [4]byte{10, 61, 8, 71}, [4]byte{10, 0, 0, 1}
	obs := &PrivateUDPObservations{contacts: map[pollContact]struct{}{{manager, device, "imsi-a", 45000}: {}}}
	request := Record{SrcIP: manager, DstIP: device, DstPort: 161, Protocol: ProtocolUDP, FleetIdentity: "imsi-a"}
	oldReturn := Record{SrcIP: device, DstIP: manager, DstPort: 45000, Protocol: ProtocolUDP, FleetIdentity: "imsi-a", returnEvidence: unverifiedReturn}
	newReturn := oldReturn
	newReturn.FleetIdentity = "imsi-b"
	unknown := oldReturn
	unknown.FleetIdentity = ""
	unknown.returnEvidence = decodedResponse
	listeners, targets := obs.PrivateEndpointBehaviors([]Record{oldReturn, newReturn, unknown}, []Record{request})
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

// File collectors discarded before TakePacketBatch must not suppress a listener.
func TestPollContactsFromCompletedBatchesOnly(t *testing.T) {
	state := &PrivateUDPObservations{}
	client, device := [4]byte{10, 61, 8, 71}, [4]byte{10, 0, 0, 1}
	for _, port := range []uint16{44000, 45000, 46000} {
		c := NewCollectorWithOptions(ScanOptions{PrivateUDP: state})
		c.pollContacts = map[pollContact]struct{}{{client, device, "", port}: {}}
		if port != 45000 {
			c.TakePacketBatch()
		}
	}
	var returns []Record
	for _, port := range []uint16{44000, 45000, 46000} {
		returns = append(returns, Record{SrcIP: device, DstIP: client, DstPort: port, Protocol: ProtocolUDP, returnEvidence: unverifiedReturn})
	}
	listeners, _ := state.PrivateEndpointBehaviors(returns, nil)
	if len(listeners) != 1 || listeners[0].DstPort != 45000 {
		t.Fatalf("listeners after discarding partial file: %+v", listeners)
	}
}
