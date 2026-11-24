package syntrail

import (
	"encoding/hex"
	"testing"
)

func TestRecognizeResponse(t *testing.T) {
	// This binding contains sysUpTime.0 with TimeTicks value 1.
	const response = "a219020101020100020100300e300c06072b060102010300430101"
	const msg = "3021020101040178" + response
	const v3Header = "300d020101020205dc040100020103"
	for _, tc := range []struct {
		name, wire string
		want       bool
	}{
		{"v1", "3021020100040178" + response, true},
		{"v2c", msg, true},
		{"v3 plaintext", "3035020103" + v3Header + "0400301f04000400" + response, true},
		{"v3 encrypted", "3019020103300d020101020205dc04010302010304000403616263", false},
		{"unsupported version", "3021020102040178" + response, false},
		{"request", "3013020101040178a00b0201010201000201003000", false},
		{"trailing bytes", msg + "00", false},
		{"truncated", msg[:len(msg)-2], false},
		{"incomplete binding", "3015020101040178a20d02010102010002010030023000", false},
		{"bad integer", "3012020101040178a20a02000201000201003000", false},
		{"indefinite length", "3080020101040178" + response + "0000", false},
		{"valid long length form", "308121020101040178" + response, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire, err := hex.DecodeString(tc.wire)
			if err != nil {
				t.Fatal(err)
			}
			if got := isSNMPResponse(wire); got != tc.want {
				t.Errorf("recognized %t, want %t", got, tc.want)
			}
		})
	}
}

func FuzzSNMPResponse(f *testing.F) {
	wire, _ := hex.DecodeString("3013020101040178a20b0201010201000201003000")
	f.Add(wire)
	f.Add([]byte{0x30, 0xfe, 0xff})
	f.Fuzz(func(t *testing.T, p []byte) { isSNMPResponse(p) })
}
