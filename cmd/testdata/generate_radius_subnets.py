"""Generate the offline RADIUS/subnet/SNI contract fixture (no real traffic)."""
import ipaddress
from pathlib import Path
import struct


def ip(value):
    return ipaddress.IPv4Address(value).packed


def frame(src, dst, proto, payload):
    # VLAN 2511 reproduces Stone's encapsulation using wholly synthetic traffic.
    ethernet = bytes.fromhex('00112233445566778899aabb810009cf0800')
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, ip(src), ip(dst))
    return ethernet + header + payload


def udp(src, dst, sport, dport, payload):
    return frame(src, dst, 17, struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload)


def tcp(src, dst, sport, dport, flags, payload=b'', seq=1):
    return frame(src, dst, 6, struct.pack('!HHIIBBHHH', sport, dport, seq, 1, 0x50, flags, 65535, 0, 0) + payload)


def radius(address, imsi, sid, nas='10.181.1.1', status=1, duration=None):
    def attr(kind, value):
        return bytes([kind, len(value) + 2]) + value
    attrs = attr(1, imsi.encode()) + attr(8, ip(address)) + attr(40, struct.pack('!I', status)) + attr(44, sid.encode())
    if duration is not None:
        attrs += attr(46, struct.pack('!I', duration))
    payload = struct.pack('!BBH', 4, len(sid), 20 + len(attrs)) + bytes(16) + attrs
    return udp(nas, '10.250.0.99', 35000, 1813, payload)


def radius_response():
    payload = struct.pack('!BBH', 5, 1, 20) + bytes(16)
    return udp('10.250.0.99', '10.181.1.1', 1813, 35000, payload)


def hello(name):
    host = name.encode()
    names = b'\x00' + struct.pack('!H', len(host)) + host
    value = struct.pack('!H', len(names)) + names
    extension = struct.pack('!HH', 0, len(value)) + value
    body = b'\x03\x03' + bytes(32) + b'\x00\x00\x02\x00\x2f\x01\x00' + struct.pack('!H', len(extension)) + extension
    handshake = b'\x01' + len(body).to_bytes(3, 'big') + body
    return b'\x16\x03\x03' + struct.pack('!H', len(handshake)) + handshake


packets = [
    (0, radius('10.181.1.10', '123456789012345', 'first')),
    (0, radius_response()),
    (1, tcp('10.181.1.10', '10.250.0.5', 40000, 1883, 2)),
    (2, udp('10.181.1.10', '10.250.0.6', 41000, 514, b'<34>Oct 11 22:14:15 host app: first')),
    (3, tcp('10.181.1.10', '203.0.113.10', 42000, 443, 2)),
    (4, tcp('203.0.113.10', '10.181.1.10', 443, 42000, 18)),
    (5, tcp('10.181.1.10', '203.0.113.10', 42000, 443, 24, hello('device.example.test'), 2)),
    (10, radius('10.181.1.10', '223456789012345', 'second')),
    (11, tcp('10.181.1.10', '10.250.0.5', 40001, 1883, 2)),
    (12, udp('10.181.1.10', '10.250.0.6', 41001, 514, b'<34>Oct 11 22:14:15 host app: second')),
    (13, radius('10.181.1.11', '123456789012345', 'third', nas='192.0.2.10')),
    (14, tcp('10.181.1.11', '10.250.0.5', 40002, 1883, 2)),
    (15, udp('10.181.1.11', '10.250.0.6', 41002, 514, b'<34>Oct 11 22:14:15 host app: third')),
    (16, tcp('10.181.1.12', '10.250.0.5', 40003, 1883, 2)),
    (17, tcp('10.250.0.7', '10.181.1.10', 43000, 22, 2)),
    (18, tcp('198.51.100.1', '203.0.113.7', 44000, 443, 2)),
    (19, tcp('198.51.100.1', '203.0.113.7', 44000, 443, 24, hello('excluded.example.test'), 2)),
    (25, tcp('10.181.1.10', '10.250.0.8', 45000, 8883, 2)),
]
# Three owners reuse one IP/endpoint. Late packets exceed the 128-time cap;
# pruning across owners would silently discard the middle device.
for start, imsi in [(30, '323456789012345'), (40, '423456789012345'), (50, '523456789012345')]:
    packets += [
        (start, radius('10.181.2.10', imsi, 'reuse-' + imsi)),
        (start + 1, tcp('10.181.2.10', '203.0.113.20', 46000, 443, 2)),
        (start + 2, tcp('203.0.113.20', '10.181.2.10', 443, 46000, 18)),
        (start + 3, tcp('10.181.2.10', '203.0.113.20', 46000, 443, 24, hello('reused.example.test'), 2)),
    ]
packets += [(54 + n / 100, tcp('10.181.2.10', '203.0.113.20', 46000, 443, 16)) for n in range(200)]
packets += [
    (70, radius('10.181.2.10', '523456789012345', 'reuse-523456789012345', status=2, duration=20)),
    (71, tcp('10.181.2.10', '203.0.113.20', 46000, 443, 2)),
    (72, tcp('203.0.113.20', '10.181.2.10', 443, 46000, 18)),
    (73, tcp('10.181.2.10', '203.0.113.20', 46000, 443, 24, hello('reused.example.test'), 2)),
]
output = bytearray(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
for offset, packet in sorted(packets, key=lambda item: item[0]):
    seconds, micros = divmod(round(offset * 1000000), 1000000)
    output += struct.pack('<IIII', 1793491200 + seconds, micros, len(packet), len(packet)) + packet
Path(__file__).with_name('radius-subnets.pcap').write_bytes(output)
