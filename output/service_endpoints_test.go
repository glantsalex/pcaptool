package output

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/aglants/pcaptool/internal/dns"
)

func TestWriteServiceEndpointsJSON_ValidArray(t *testing.T) {
	in := []dns.ServiceEndpoint{
		{
			IP:         "34.120.10.1",
			DNS:        "api.example.com",
			Protocol:   "tcp",
			Port:       443,
			PeersCount: 7,
			HashVal:    123456,
			ObservedAt: 1738576352000,
		},
	}

	var b bytes.Buffer
	if err := WriteServiceEndpointsJSON(&b, in); err != nil {
		t.Fatalf("WriteServiceEndpointsJSON error: %v", err)
	}

	var out []dns.ServiceEndpoint
	if err := json.Unmarshal(b.Bytes(), &out); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, b.String())
	}
	if len(out) != 1 {
		t.Fatalf("len(out)=%d, want 1", len(out))
	}
	if out[0].IP != in[0].IP ||
		out[0].DNS != in[0].DNS ||
		out[0].Protocol != in[0].Protocol ||
		out[0].Port != in[0].Port ||
		out[0].PeersCount != in[0].PeersCount ||
		out[0].ObservedAt != in[0].ObservedAt {
		t.Fatalf("unexpected roundtrip: got=%#v want=%#v", out[0], in[0])
	}
}
