package cmd

import (
	"github.com/aglants/pcaptool/internal/direction"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Execute the generated SELECT, translating only BigQuery IP helpers and the
// source name. SQLite checks row/cardinality semantics; staging must still check
// BigQuery's materialized-view DDL support and permissions.
func TestDirectionSQLRowSemantics(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 required for offline SQL execution")
	}
	d := direction.Document{Endpoints: []direction.Endpoint{
		{IP: "10.4.100.58", Server: direction.Server{Listeners: []direction.Behavior{
			{Protocol: "tcp", Port: 1883}, {Protocol: "udp", Port: 6514, Evidence: "syslog"}, {Protocol: "udp", Port: 9000},
		}}, Probe: direction.Probe{Targets: []direction.Behavior{{Protocol: "tcp", Port: 22}}}},
	}}
	path := filepath.Join(t.TempDir(), "query.sql")
	if err := os.WriteFile(path, []byte(flowDirectionCorrectionSQLForDocument("s", d)), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(python, "-c", directionSQLCheck, path).CombinedOutput()
	if err != nil {
		t.Fatalf("SQL semantics: %v\n%s", err, out)
	}
}

const directionSQLCheck = `
import ipaddress, sqlite3, sys
sql = open(sys.argv[1]).read().split('\nAS\n', 1)[1]
sql = sql.replace('NET.SAFE_IP_FROM_STRING','IP_FROM_STRING').replace('NET.IP_FROM_STRING','IP_FROM_STRING').replace('NET.IP_TRUNC','IP_TRUNC')
sql = sql.replace(chr(96)+'{{gcp_project_id}}.{{bq_dataset}}.flow-data-s'+chr(96),'flows')
def ip(value):
    try: return ipaddress.ip_address(value).packed
    except (ValueError, TypeError): return None
def trunc(value, bits):
    if value is None: return None
    a = ipaddress.ip_address(value)
    return ipaddress.ip_network(str(a)+'/'+str(bits), strict=False).network_address.packed
c = sqlite3.connect(':memory:')
c.create_function('IP_FROM_STRING',1,ip)
c.create_function('IP_TRUNC',2,trunc)
c.create_function('IF',3,lambda cond,yes,no: yes if cond else no)
columns = ['device_id','start_time','end_time','src_ip','dst_ip','src_port','dst_port','protocol','bytes_to_srv','bytes_to_client','pckt_to_srv','pckt_to_client']
c.execute('CREATE TABLE flows ('+','.join(columns)+')')
server, device = '10.4.100.58', '10.2.3.4'
cases = [
 ('server_response',server,device,1883,50000,'TCP',True),
 ('server_request',device,server,50000,1883,'tcp',False),
 ('probe_request',server,device,50000,22,'tcp',False),
 ('probe_response',device,server,22,50000,'tcp',True),
 ('both_roles',server,device,1883,22,'tcp',False),
 ('syslog_response',server,device,6514,50000,'udp',True),
 ('syslog_request',device,server,50000,6514,'udp',False),
 ('unqualified_udp',server,device,9000,50000,'udp',False),
 ('dns_response',device,server,53,50000,'udp',True),
 ('dns_request',device,server,50000,53,'udp',False),
 ('both_dns',device,server,53,53,'udp',False),
 ('dns_beats_listener',server,device,6514,53,'udp',False),
 ('unknown',device,'10.3.4.5',50000,443,'tcp',False),
 ('public_original_policy','203.0.113.2',device,443,50000,'tcp',True),
 ('null_port',server,device,None,50000,'tcp',False),
 ('unknown_protocol',server,device,1883,50000,'sctp',False),
]
expected = {}
for name,src,dst,sp,dp,proto,swap in cases:
    row = [name,'2026-09-09T00:00:00Z','2026-10-10T12:00:00Z',src,dst,sp,dp,proto,101,202,11,22]
    c.execute('INSERT INTO flows VALUES ('+','.join(['?']*len(row))+')',row)
    row[7] = proto.lower()
    if swap:
        for i,j in [(3,4),(5,6),(8,9),(10,11)]: row[i],row[j] = row[j],row[i]
    expected[name] = tuple(row)
result = c.execute(sql)
assert [d[0] for d in result.description] == columns
rows = result.fetchall()
assert len(rows) == len(cases)
for row in rows:
    assert row == expected[row[0]], (row,expected[row[0]])
`
