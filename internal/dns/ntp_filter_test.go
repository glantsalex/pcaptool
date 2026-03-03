package dns

import "testing"

func TestLooksLikeNTPDNSName(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{name: "time.esa.int", want: true},
		{name: "ntp.ubuntu.com", want: true},
		{name: "ntp1.google.com", want: true},
		{name: "time1.facebook.com", want: true},
		{name: "0.pool.ntp.org", want: true},
		{name: "foo-timesync-bar.example.com", want: true},
		{name: "api.mobilepay.dk", want: false},
		{name: "rtlgermany.payment.banksys.be", want: false},
		{name: "timestamp.api.example.com", want: false},
	}

	for _, tc := range cases {
		got := LooksLikeNTPDNSName(tc.name)
		if got != tc.want {
			t.Fatalf("LooksLikeNTPDNSName(%q)=%v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestFilterOutNTPDNSTransactions(t *testing.T) {
	keep := &DNSTransaction{
		DNSName:      "api.mobilepay.dk",
		NameEvidence: EvDNSAnswer,
	}
	drop := &DNSTransaction{
		DNSName:      "time.esa.int",
		NameEvidence: EvDNSAnswer,
	}
	keepSNI := &DNSTransaction{
		DNSName:      "time.esa.int",
		NameEvidence: EvSNI,
	}

	in := []*DNSTransaction{keep, drop, keepSNI}
	out, dropped := FilterOutNTPDNSTransactions(in)

	if dropped != 1 {
		t.Fatalf("dropped=%d, want 1", dropped)
	}
	if len(out) != 2 {
		t.Fatalf("len(out)=%d, want 2", len(out))
	}
	if out[0] != keep || out[1] != keepSNI {
		t.Fatalf("unexpected output ordering/content")
	}
}
