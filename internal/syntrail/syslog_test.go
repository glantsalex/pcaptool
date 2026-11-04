package syntrail

import (
	"net/netip"
	"testing"
)

func TestRecognizeSyslog(t *testing.T) {
	for _, s := range []string{"<140>1 2026-10-10T00:01:36.799929+00:00 HYC frontend - - -  libpng", "<142>Oct 10 00:01:37 HYC privileged: text", "<134>1 - HYC app - - - text"} {
		if !RecognizeSyslog([]byte(s)) {
			t.Fatalf("rejected %s", s)
		}
	}
	for _, s := range []string{"<140>", "hello", "<192>Oct 10 00:01:37 HYC app: text", "<140>1 2026-10-10T00:01:37Z HYC", "<140>Oct 99 00:01:37 HYC app: text", "<140>Oct 10 99:01:37 HYC app: text"} {
		if RecognizeSyslog([]byte(s)) {
			t.Fatalf("accepted %s", s)
		}
	}
	c := NewSyslogCache()
	ip := netip.MustParseAddr("10.4.100.58")
	if c.Qualify(ip, 6514, []byte("short")) {
		t.Fatal("qualified invalid")
	}
	if !c.Qualify(ip, 6514, []byte("<140>Oct 10 00:01:37 host app: text")) || !c.Qualify(ip, 6514, nil) || c.Known(ip, 6515) {
		t.Fatal("cache scope")
	}
}
func BenchmarkSyslogHeader(b *testing.B) {
	p := []byte("<140>1 2026-10-10T00:01:36.799929+00:00 HYC frontend - - -  libpng")
	b.ReportAllocs()
	for b.Loop() {
		RecognizeSyslog(p)
	}
}
func BenchmarkSyslogCached(b *testing.B) {
	c := NewSyslogCache()
	ip := netip.MustParseAddr("10.4.100.58")
	c.Add(ip, 6514)
	b.ReportAllocs()
	for b.Loop() {
		c.Qualify(ip, 6514, nil)
	}
}
