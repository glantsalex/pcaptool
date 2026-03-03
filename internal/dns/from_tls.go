// Copyright © 2025 Alex Glants
// All rights reserved.
// This file is part of pcaptool—the thing I built because
// “just scroll in Wireshark forever” is not a real strategy.
// Use it, tweak it, extend it—but do not pretend you wrote it.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// BuildSNITransactionsFromPCAPs scans PCAP files for non-truncated TLS ClientHello
// packets with SNI, and returns synthetic DNSTransactions representing
// IssuerIP -> SNI -> DstIP:port.
//
// These transactions already have DestinationPort and ResolvedIPs set and do
// NOT need further correlation.
func BuildSNITransactionsFromPCAPs(ctx context.Context, files []string) ([]*DNSTransaction, error) {
	var (
		mu   sync.Mutex
		out  []*DNSTransaction
		wg   sync.WaitGroup
		errC = make(chan error, len(files))
	)

	// To avoid duplicate entries (e.g. retransmits), dedup by issuer+dstIP+port+SNI.
	type key struct {
		issuer string
		dstIP  string
		port   uint16
		sni    string
	}
	seen := make(map[key]struct{})

	worker := func(path string) {
		defer wg.Done()

		handle, err := pcap.OpenOffline(path)
		if err != nil {
			errC <- fmt.Errorf("open pcap for TLS SNI: %w", err)
			return
		}
		defer handle.Close()

		src := gopacket.NewPacketSource(handle, handle.LinkType())
		for {
			select {
			case <-ctx.Done():
				return
			case pkt, ok := <-src.Packets():
				if !ok {
					return
				}

				// Skip truncated packets
				if md := pkt.Metadata(); md != nil && md.Truncated {
					continue
				}

				// We only care about TCP
				tcpLayer := pkt.Layer(layers.LayerTypeTCP)
				if tcpLayer == nil {
					continue
				}
				tcp, _ := tcpLayer.(*layers.TCP)
				if tcp == nil {
					continue
				}
				if len(tcp.Payload) == 0 {
					continue
				}

				sni, ok := extractSNIFromClientHello(tcp.Payload)
				if !ok || sni == "" {
					continue
				}

				// Get IPs
				networkLayer := pkt.NetworkLayer()
				if networkLayer == nil {
					continue
				}
				srcIP, dstIP := net.IP(nil), net.IP(nil)
				switch nl := networkLayer.(type) {
				case *layers.IPv4:
					srcIP = nl.SrcIP
					dstIP = nl.DstIP
				case *layers.IPv6:
					srcIP = nl.SrcIP
					dstIP = nl.DstIP
				default:
					continue
				}
				if srcIP == nil || dstIP == nil {
					continue
				}

				port := uint16(tcp.DstPort)
				if port == 0 {
					continue
				}

				k := key{
					issuer: srcIP.String(),
					dstIP:  dstIP.String(),
					port:   port,
					sni:    sni,
				}

				mu.Lock()
				if _, exists := seen[k]; exists {
					mu.Unlock()
					continue
				}
				seen[k] = struct{}{}
				mu.Unlock()

				// Build synthetic DNSTransaction from SNI
				dp := port
				tx := &DNSTransaction{
					RequestTime:     pkt.Metadata().Timestamp,
					IssuerIP:        append(net.IP(nil), srcIP...),
					DNSName:         sni,
					NameEvidence:    EvSNI, // NEW
					ResolverIP:      nil,
					DestinationPort: &dp,
					PCAPFile:        path,
					Candidates:      nil,
					ProtocolL4:      L4ProtoTCP,
				}

				// Add resolved IP with evidence.
				// SNI implies real established TCP, so we mark it as observed connectivity too.
				tx.AddResolvedIP(append(net.IP(nil), dstIP...), EvSNI|EvObservedConn)

				mu.Lock()
				out = append(out, tx)
				mu.Unlock()
			}
		}
	}

	for _, f := range files {
		wg.Add(1)
		go worker(f)
	}

	wg.Wait()
	close(errC)

	for e := range errC {
		if e != nil {
			return nil, e
		}
	}

	// Sort by RequestTime to keep behavior deterministic (optional but nice)
	if len(out) > 1 {
		sort.Slice(out, func(i, j int) bool {
			ti := out[i].RequestTime
			tj := out[j].RequestTime
			if ti.Equal(tj) {
				return out[i].DNSName < out[j].DNSName
			}
			return ti.Before(tj)
		})
	}

	return out, nil
}
