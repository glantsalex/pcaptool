package cmd

import (
	"context"
	"encoding/json"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/aglants/pcaptool/internal/direction"
)

func directionFixture(t *testing.T, name string) direction.Document {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "flow_direction", name+".registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := direction.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.ValidateRegistry(d.AccountID, d.StreamID); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestDirectionSQLSnapshotsAndIndependentBaseline(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("python3 is required for independent SQL equivalence tests")
	}
	for _, name := range []string{"empty", "single", "mixed", "404163-1"} {
		t.Run(name, func(t *testing.T) {
			d := directionFixture(t, name)
			sql := flowDirectionCorrectionSQLForDocument(d.StreamID, d)
			golden, err := os.ReadFile(filepath.Join("testdata", "flow_direction", name+".sql"))
			if err != nil {
				t.Fatal(err)
			}
			if sql != string(golden) {
				t.Fatalf("generated SQL differs from reviewed snapshot %s.sql", name)
			}
			assertDirectionFormatting(t, sql)
			path := filepath.Join(t.TempDir(), "generated.sql")
			if err = os.WriteFile(path, []byte(sql), 0600); err != nil {
				t.Fatal(err)
			}
			before := filepath.Join("testdata", "flow_direction", name+".before.sql")
			output, err := exec.Command(python, filepath.Join("testdata", "flow_direction", "compare_sql.py"), before, path).CombinedOutput()
			if err != nil {
				t.Fatalf("baseline equivalence: %v\n%s", err, output)
			}
			t.Log(strings.TrimSpace(string(output)))
		})
	}
}

func assertDirectionFormatting(t *testing.T, sql string) {
	t.Helper()
	if strings.Contains(sql, `\n`) {
		t.Fatal("literal escaped newlines in SQL")
	}
	for i, line := range strings.Split(sql, "\n") {
		if len(line) > directionSQLLineWidth {
			t.Fatalf("line %d exceeds width: %d", i+1, len(line))
		}
		if strings.Contains(line, "WHEN ") && strings.Contains(line, "THEN ") {
			t.Fatalf("single-line CASE branch: %s", line)
		}
		if strings.Contains(line, "THEN ") && !strings.HasPrefix(line, "        THEN ") {
			t.Fatalf("THEN alignment: %s", line)
		}
	}
	for _, want := range []string{
		"WITH parsed AS (", "\nbase AS (", "\nlearned AS (", "\ndecide AS (",
		"      WHEN NOT src_is_private\n        AND dst_is_private\n        THEN 'public_to_private_artifact'",
		"      WHEN src_is_private AND dst_is_private\n        AND protocol_lc = 'udp'\n        AND src_port = 53\n        AND dst_port != 53\n        THEN 'udp_dns_response'",
	} {
		if !strings.Contains(sql, want) {
			t.Fatalf("format missing %q", want)
		}
	}
	if strings.Contains(sql, "SELECT\n    *") || strings.Contains(sql, "SELECT *") {
		t.Fatal("implicit projection")
	}
	if strings.Count(sql, "NET.SAFE_IP_FROM_STRING(src_ip)") != 1 || strings.Count(sql, "NET.SAFE_IP_FROM_STRING(dst_ip)") != 1 {
		t.Fatal("IP parsing not named once")
	}
}

func TestDirectionRuleMirrorsMatchActualBaseline(t *testing.T) {
	d := directionFixture(t, "404163-1")
	rules := directionRules(d)
	before, err := os.ReadFile(filepath.Join("testdata", "flow_direction", "404163-1.before.sql"))
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`\(protocol_lc = '(tcp|udp)' AND (src_ip|dst_ip) = '([^']+)' AND (src_port|dst_port) = ([0-9]+)\)`)
	split := strings.SplitN(string(before), " AND NOT (", 2)
	if len(split) != 2 {
		t.Fatal("baseline missing forward suppression")
	}
	reverse, forward := re.FindAllStringSubmatch(split[0], -1), re.FindAllStringSubmatch(split[1], -1)
	if len(reverse) != 71 || len(forward) != 71 || len(rules) != 71 {
		t.Fatal("reviewed fixture changed")
	}
	render := func(r directionRule) string {
		return r.protocol + "/" + r.ipSide.column("ip") + "/" + r.ip + "/" + r.portSide.column("port") + "/" + fmtPort(r.port)
	}
	want := map[string]bool{}
	wantForward := map[string]bool{}
	for _, m := range reverse {
		want[strings.Join(m[1:], "/")] = true
	}
	for _, m := range forward {
		wantForward[strings.Join(m[1:], "/")] = true
	}
	if len(want) != 71 || len(wantForward) != 71 {
		t.Fatal("baseline contains duplicates")
	}
	for _, r := range rules {
		if !want[render(r)] || !wantForward[render(r.mirror())] {
			t.Fatalf("lost rule or exact mirror: %+v", r)
		}
		if r.mirror().mirror() != r {
			t.Fatal("mirror is not an involution")
		}
	}
	if len(groupDirectionRules(rules)) != 38 {
		t.Fatal("actual fixture grouping changed")
	}
}

func TestDirectionGroupingAndDeterminism(t *testing.T) {
	d := directionFixture(t, "mixed")
	reference := flowDirectionCorrectionSQLForDocument(d.StreamID, d)
	rules := directionRules(d)
	groups := groupDirectionRules(rules)
	want := map[directionRule]bool{}
	for _, r := range rules {
		want[r] = true
	}
	for _, g := range groups {
		for _, port := range g.ports {
			r := directionRule{g.key.protocol, g.key.ipSide, g.key.ip, g.key.portSide, port}
			if !want[r] {
				t.Fatalf("group introduced rule: %+v", r)
			}
			delete(want, r)
		}
	}
	if len(want) != 0 {
		t.Fatal("group lost scalar rules")
	}
	// Independent selectors, protocol and IP all distinguish groups.
	base := directionRule{"tcp", directionSource, "10.0.0.1", directionSource, 80}
	variants := []directionRule{base, base.mirror(), {"tcp", directionDestination, "10.0.0.1", directionSource, 80}, {"udp", directionSource, "10.0.0.1", directionSource, 80}, {"tcp", directionSource, "10.0.0.2", directionSource, 80}}
	if len(groupDirectionRules(variants)) != len(variants) {
		t.Fatal("merged incompatible qualifiers")
	}
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 20; i++ {
		rng.Shuffle(len(d.Endpoints), func(i, j int) { d.Endpoints[i], d.Endpoints[j] = d.Endpoints[j], d.Endpoints[i] })
		for j := range d.Endpoints {
			e := &d.Endpoints[j]
			rng.Shuffle(len(e.Server.Listeners), func(a, b int) {
				e.Server.Listeners[a], e.Server.Listeners[b] = e.Server.Listeners[b], e.Server.Listeners[a]
			})
			rng.Shuffle(len(e.Probe.Targets), func(a, b int) { e.Probe.Targets[a], e.Probe.Targets[b] = e.Probe.Targets[b], e.Probe.Targets[a] })
		}
		if got := flowDirectionCorrectionSQLForDocument(d.StreamID, d); got != reference {
			t.Fatal("input order changed SQL")
		}
	}
	d.Endpoints = append(d.Endpoints, d.Endpoints...)
	if got := flowDirectionCorrectionSQLForDocument(d.StreamID, d); got != reference {
		t.Fatal("duplicate rule changed SQL")
	}
	if !strings.Contains(reference, "IN (\n") {
		t.Fatal("long port list not wrapped")
	}
}

func TestDirectionDNSGuardDependsOnLearnedUDP(t *testing.T) {
	for _, name := range []string{"empty", "single", "404163-1", "mixed"} {
		d := directionFixture(t, name)
		sql := flowDirectionCorrectionSQLForDocument(d.StreamID, d)
		if strings.Contains(sql, "AND (src_port = 53 OR dst_port = 53)") != (name == "mixed") {
			t.Fatalf("wrong DNS guard for %s", name)
		}
	}
	d := directionFixture(t, "mixed")
	before, _ := json.Marshal(d)
	_ = flowDirectionCorrectionSQLForDocument(d.StreamID, d)
	after, _ := json.Marshal(d)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("renderer mutated registry")
	}
}

func TestDirectionCLIAndDailyRenderingShareFormatting(t *testing.T) {
	d := directionFixture(t, "mixed")
	out := filepath.Join(t.TempDir(), "rendered.sql")
	root := newRootCommand()
	root.SetArgs([]string{"render-flow-direction-sql", "--net-id", d.StreamID, "--account", d.AccountID, "--registry", filepath.Join("testdata", "flow_direction", "mixed.registry.json"), "--output", out, "--no-banner"})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != flowDirectionCorrectionSQLForDocument(d.StreamID, d) {
		t.Fatal("CLI changed formatted SQL")
	}
}

func fmtPort(p uint16) string { return strconv.Itoa(int(p)) }
