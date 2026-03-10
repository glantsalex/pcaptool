package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/aglants/pcaptool/internal/dns"
)

// WriteIPDNSAppendAuditTable writes provenance for newly appended DNS,IP pairs.
func WriteIPDNSAppendAuditTable(w io.Writer, rows []dns.IPDNSAppendAuditRecord) error {
	if len(rows) == 0 {
		_, err := fmt.Fprintln(w, "No new learned IP->DNS pairs were appended.")
		return err
	}

	const (
		dnsHeader      = "DNS Name"
		ipHeader       = "IP"
		evHeader       = "Evidence"
		obsHeader      = "Observed At UTC"
		portHeader     = "Port"
		issuerHeader   = "Issuer IP"
		resolverHeader = "Resolver IP"
		fileHeader     = "PCAP File"
	)

	dnsWidth := len(dnsHeader)
	ipWidth := len(ipHeader)
	evWidth := len(evHeader)
	obsWidth := len(obsHeader)
	portWidth := len(portHeader)
	issuerWidth := len(issuerHeader)
	resolverWidth := len(resolverHeader)
	fileWidth := len(fileHeader)

	for _, r := range rows {
		if l := len(r.DNS); l > dnsWidth {
			dnsWidth = l
		}
		if l := len(r.IP); l > ipWidth {
			ipWidth = l
		}
		if l := len(r.Evidence); l > evWidth {
			evWidth = l
		}
		if l := len(r.ObservedAt); l > obsWidth {
			obsWidth = l
		}
		portStr := fmt.Sprintf("%d", r.Port)
		if r.Port == 0 {
			portStr = ""
		}
		if l := len(portStr); l > portWidth {
			portWidth = l
		}
		if l := len(r.IssuerIP); l > issuerWidth {
			issuerWidth = l
		}
		if l := len(r.ResolverIP); l > resolverWidth {
			resolverWidth = l
		}
		if l := len(r.PCAPFile); l > fileWidth {
			fileWidth = l
		}
	}

	printRow := func(dnsName, ip, ev, obs, port, issuer, resolver, file string) {
		fmt.Fprintf(
			w,
			"%-*s  %-*s  %-*s  %-*s  %-*s  %-*s  %-*s  %-*s\n",
			dnsWidth, dnsName,
			ipWidth, ip,
			evWidth, ev,
			obsWidth, obs,
			portWidth, port,
			issuerWidth, issuer,
			resolverWidth, resolver,
			fileWidth, file,
		)
	}

	sep := func(n int) string { return strings.Repeat("-", n) }

	printRow(dnsHeader, ipHeader, evHeader, obsHeader, portHeader, issuerHeader, resolverHeader, fileHeader)
	fmt.Fprintf(
		w,
		"%s  %s  %s  %s  %s  %s  %s  %s\n",
		sep(dnsWidth),
		sep(ipWidth),
		sep(evWidth),
		sep(obsWidth),
		sep(portWidth),
		sep(issuerWidth),
		sep(resolverWidth),
		sep(fileWidth),
	)

	for _, r := range rows {
		portStr := ""
		if r.Port > 0 {
			portStr = fmt.Sprintf("%d", r.Port)
		}
		printRow(r.DNS, r.IP, r.Evidence, r.ObservedAt, portStr, r.IssuerIP, r.ResolverIP, r.PCAPFile)
	}

	fmt.Fprintf(
		w,
		"%s  %s  %s  %s  %s  %s  %s  %s\n",
		sep(dnsWidth),
		sep(ipWidth),
		sep(evWidth),
		sep(obsWidth),
		sep(portWidth),
		sep(issuerWidth),
		sep(resolverWidth),
		sep(fileWidth),
	)
	return nil
}
