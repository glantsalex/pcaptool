// Copyright © 2025 Alex Glants
// All rights reserved.
// This file is part of pcaptool—the thing I built because
// “just scroll in Wireshark forever” is not a real strategy.
// Use it, tweak it, extend it—but do not pretend you wrote it.
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"encoding/csv"
	"fmt"
	"os"
	"strings"

	"github.com/aglants/pcaptool/internal/dns"
)

func WriteCSV(path string, records []dns.OutputRecord) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	_ = w.Write([]string{
		"request_time",
		"issuer_ip",
		"dns_name",
		"resolved_ips",
		"resolver_ip",
		"destination_port",
	})

	for _, r := range records {
		resolver := ""
		if r.ResolverIP != nil {
			resolver = *r.ResolverIP
		}
		destPort := ""
		if r.DestinationPort != nil {
			destPort = fmt.Sprintf("%d", *r.DestinationPort)
		}

		_ = w.Write([]string{
			r.RequestTimeStr,
			r.IssuerIP,
			r.DNSName,
			strings.Join(r.ResolvedIPs, ";"),
			resolver,
			destPort,
		})
	}

	return w.Error()
}
