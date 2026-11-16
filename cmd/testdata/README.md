# Synthetic capture fixtures

## radius-subnets.pcap

Synthetic 2026-11-01 traffic, no customer data. Regenerate with
`python3 generate_radius_subnets.py` from this directory. Includes RADIUS Start
records between non-fleet NAS/server addresses, dynamic IP reuse, one IMSI on two
IPs, unmatched fleet traffic, TLS SNI, private TCP servers, qualified UDP syslog,
a probe, an out-of-pool SNI connection and traffic after the final accounting record.
All addresses/identities are fixture values. Tests disable network enrichment.

Frames carry 802.1Q VLAN 2511. This guards against the DNS/SNI capture filter
silently discarding tagged traffic before extraction. Unit tests also cover
untagged and double-tagged frames in PCAP and PCAPNG.

RADIUS requests include a NAS inside the device pool and one outside it.
The in-pool NAS also receives an Accounting-Response. All requests must feed
Pass 1; the RADIUS server `10.250.0.99` must not appear in later traffic artifacts.
