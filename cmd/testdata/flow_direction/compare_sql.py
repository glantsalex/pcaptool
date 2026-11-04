"""Compare frozen pre-refactor SQL and generated SQL, independently of Go helpers.

SQLite exercises scalar SQL three-valued logic; the adapters implement the existing
BigQuery IP helpers and IF. This does not certify BigQuery MV DDL eligibility/types.
"""
import collections
import ipaddress
import itertools
import random
import re
import sqlite3
import sys
from pathlib import Path

before, after = (Path(p).read_text() for p in sys.argv[1:])
pattern = r"\(protocol_lc = '(tcp|udp)' AND (src_ip|dst_ip) = '([^']+)' AND (src_port|dst_port) = ([0-9]+)\)"
parts = before.split(' AND NOT (', 1)
reverse = re.findall(pattern, parts[0]) if len(parts) == 2 else []
forward = re.findall(pattern, parts[1]) if len(parts) == 2 else []
columns = ['device_id','start_time','end_time','src_ip','dst_ip','src_port','dst_port','protocol','bytes_to_srv','bytes_to_client','pckt_to_srv','pckt_to_client']
networks = [ipaddress.ip_network(x) for x in ['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','100.64.0.0/10']]

def private(value):
    try:
        a = ipaddress.ip_address(value)
        return a.version == 4 and any(a in n for n in networks)
    except (ValueError, TypeError): return False

def eq(a, b): return None if a is None or b is None else a == b

def and3(*xs): return False if False in xs else None if None in xs else True

def or3(xs):
    xs = list(xs)
    return True if True in xs else None if None in xs else False

def not3(x): return None if x is None else not x

def match(rules, row):
    protocol = row['protocol'].lower() if row['protocol'] is not None else None
    return or3(and3(eq(protocol,p),eq(row[ip_side],ip),eq(row[port_side],int(port))) for p,ip_side,ip,port_side,port in rules)

def reason(row):
    sp, dp = private(row['src_ip']), private(row['dst_ip'])
    proto = row['protocol'].lower() if row['protocol'] is not None else None
    if not sp and dp: return 'public_to_private_artifact'
    if and3(sp,dp,eq(proto,'udp'),eq(row['src_port'],53),not3(eq(row['dst_port'],53))) is True: return 'udp_dns_response'
    if and3(sp,dp,eq(proto,'udp'),or3([eq(row['src_port'],53),eq(row['dst_port'],53)])) is True: return None
    if and3(sp,dp,match(reverse,row),not3(match(forward,row))) is True: return 'learned_endpoint_reversed'
    return None

rows = []
def add(src='10.254.254.250',dst='10.254.254.251',sp=49151,dp=49152,proto='tcp'):
    row = dict(zip(columns,[f'device-{len(rows)}','2026-09-09T00:00:00Z','2026-10-10T12:00:00Z',src,dst,sp,dp,proto,101,202,11,22]))
    rows.append(row)
    return row

# Each frozen scalar rule and its exact mirror, with null selectors and protocol variants.
mirror = {'src_ip':'dst_ip','dst_ip':'src_ip','src_port':'dst_port','dst_port':'src_port'}
for p,ips,ip,ps,port in reverse:
    for reflected in [False,True]:
        for proto in [p,p.upper(),None,'sctp']:
            row = add(proto=proto)
            row[mirror[ips] if reflected else ips] = ip
            row[mirror[ps] if reflected else ps] = int(port)
            for field in ['src_ip','dst_ip','src_port','dst_port']:
                variant = dict(row);variant[field]=None;variant['device_id']=f'device-{len(rows)}';rows.append(variant)

# Combine evidence to exercise conflicts. Expected decisions come from frozen scalar rules.
for a,b in itertools.product(reverse[:100],repeat=2):
    row=add(proto=a[0]);row[a[1]]=a[2];row[a[3]]=int(a[4]);row[mirror[b[1]]]=b[2];row[mirror[b[3]]]=int(b[4])

addresses = [None,'invalid','::1','fd00::1','::ffff:10.0.0.1','8.8.8.8','10.0.0.0','10.255.255.255','172.15.255.255','172.16.0.0','172.31.255.255','172.32.0.0','192.168.0.0','192.168.255.255','100.63.255.255','100.64.0.0','100.127.255.255','100.128.0.0']
for addr,proto in itertools.product(addresses,[None,'TCP','tcp','udp','UDP','sctp']):
    add(src=addr,proto=proto);add(dst=addr,proto=proto)
# DNS includes nullable ports and collisions with qualified syslog/DNS listeners.
for src,dst in [('10.4.100.58','10.4.100.59'),('10.4.100.59','10.4.100.58'),('8.8.8.8','10.4.100.58')]:
    for sp,dp in itertools.product([None,53,6514,49152],repeat=2):add(src,dst,sp,dp,'udp')
for p,ips,ip,ps,port in reverse:
    if ips == 'src_ip' and ps == 'src_port' and p == 'tcp':
        row=add(ip,ip,int(port),None,'tcp')
        assert match(reverse,row) is True and match(forward,row) is None
        assert reason(row) is None
        break
rng=random.Random(42)
for _ in range(300):
    add(rng.choice(addresses),rng.choice(addresses),rng.choice([None,0,22,53,80,443,6514,65535]),rng.choice([None,0,22,53,80,443,6514,65535]),rng.choice([None,'TCP','udp','other']))
# Real duplicate rows, not merely rows sharing a five-tuple.
rows.extend([dict(r) for r in rows[:20] for _ in range(2)])

c=sqlite3.connect(':memory:')
def ip(value):
    try:return ipaddress.ip_address(value).packed
    except (ValueError,TypeError):return None

def trunc(value,bits):
    if value is None:return None
    return ipaddress.ip_network(str(ipaddress.ip_address(value))+'/'+str(bits),strict=False).network_address.packed
c.create_function('IP_FROM_STRING',1,ip)
c.create_function('IP_TRUNC',2,trunc)
c.create_function('IF',3,lambda condition,yes,no:yes if condition else no)
c.execute('CREATE TABLE flows ('+','.join(columns)+')')
c.executemany('INSERT INTO flows VALUES ('+','.join(['?']*len(columns))+')',[[r[k] for k in columns] for r in rows])

def query(sql):
    sql=sql.split('\nAS\n',1)[1]
    sql=re.sub(r'`\{\{gcp_project_id\}\}\.\{\{bq_dataset\}\}\.flow-data-[^`]+`','flows',sql)
    return sql.replace('NET.SAFE_IP_FROM_STRING','IP_FROM_STRING').replace('NET.IP_FROM_STRING','IP_FROM_STRING').replace('NET.IP_TRUNC','IP_TRUNC')

expected=[]
for row in rows:
    r=dict(row)
    if reason(r):
        for a,b in [('src_ip','dst_ip'),('src_port','dst_port'),('bytes_to_srv','bytes_to_client'),('pckt_to_srv','pckt_to_client')]:r[a],r[b]=r[b],r[a]
    if r['protocol'] is not None:r['protocol']=r['protocol'].lower()
    expected.append(tuple(r[k] for k in columns))
expected=collections.Counter(expected)
expected_reasons=collections.Counter((r['device_id'],reason(r)) for r in rows)
for label,sql in [('baseline',before),('refactored',after)]:
    q=query(sql)
    result=c.execute(q)
    assert [col[0] for col in result.description]==columns,(label,'column order changed')
    actual=collections.Counter(result.fetchall())
    assert actual==expected,(label,'different rows/multiplicities',list((actual-expected).items())[:3],list((expected-actual).items())[:3])
    q=q.rsplit('\nSELECT\n',1)[0]+'\nSELECT device_id, swap_reason FROM decide'
    actual_reasons=collections.Counter(c.execute(q).fetchall())
    assert actual_reasons==expected_reasons,(label,'different reasons',list((actual_reasons-expected_reasons).items())[:3])
print(f'Equivalent: {len(rows)} rows including duplicates; {len(reverse)} learned rules and mirrors; all columns and reasons.')
