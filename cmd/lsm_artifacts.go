package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/aglants/pcaptool/internal/dns"
	"github.com/aglants/pcaptool/internal/logicalservice"
	"github.com/aglants/pcaptool/internal/lsm"
	"gopkg.in/yaml.v3"
)

func writeLSMArtifacts(ctx context.Context, om *OutputManager, rows []dns.TopologyEntry, definitions *logicalservice.Definitions) (map[string]string, lsm.Stats, error) {
	model, stats, err := lsm.Build(ctx, rows, definitions, om.NetID(), om.PCAPDate())
	if err != nil {
		return nil, lsm.Stats{}, err
	}
	compact, err := model.Compact()
	if err != nil {
		return nil, lsm.Stats{}, err
	}
	prefix := om.NetID() + "-" + strings.ReplaceAll(om.PCAPDate(), "-", "")
	snapshot, err := yaml.Marshal(definitions)
	if err != nil {
		return nil, lsm.Stats{}, fmt.Errorf("encode LSM definitions: %w", err)
	}
	artifacts := []struct {
		key, suffix string
		value       any
		compact     bool
		raw         []byte
	}{
		{key: "logical_services_definitions", suffix: "logical-services.yaml", raw: snapshot},
		{key: "logical_services_full", suffix: "device-services.full.json", value: model},
		{key: "logical_services_compact", suffix: "device-services.compact.json", value: compact, compact: true},
		{key: "logical_services_short", suffix: "device-services.short.json", value: model.Short()},
		{key: "logical_services_summary", suffix: "logical-services-summary.json", value: stats},
	}
	type staged struct{ key, tmp, path string }
	pending := []staged{}
	defer func() {
		for _, f := range pending {
			_ = os.Remove(f.tmp)
		}
	}()
	for _, a := range artifacts {
		if err := ctx.Err(); err != nil {
			return nil, lsm.Stats{}, err
		}
		path := om.Path(prefix + "-" + a.suffix)
		if _, err := os.Stat(path); err == nil {
			return nil, lsm.Stats{}, fmt.Errorf("LSM artifact already exists: %s", path)
		} else if !os.IsNotExist(err) {
			return nil, lsm.Stats{}, err
		}
		f, err := os.CreateTemp(om.RunDir(), ".lsm-*")
		if err != nil {
			return nil, lsm.Stats{}, err
		}
		pending = append(pending, staged{a.key, f.Name(), path})
		if a.raw != nil {
			_, err = f.Write(a.raw)
		} else {
			enc := json.NewEncoder(f)
			if !a.compact {
				enc.SetIndent("", "  ")
			}
			err = enc.Encode(a.value)
		}
		closeErr := f.Close()
		if err != nil {
			return nil, lsm.Stats{}, fmt.Errorf("write %s: %w", path, err)
		}
		if closeErr != nil {
			return nil, lsm.Stats{}, fmt.Errorf("close %s: %w", path, closeErr)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, lsm.Stats{}, err
	}
	paths := map[string]string{}
	published := []string{}
	for _, f := range pending {
		if err := os.Rename(f.tmp, f.path); err != nil {
			// These paths were created by this call in a new run directory.
			for _, path := range published {
				_ = os.Remove(path)
			}
			return nil, lsm.Stats{}, fmt.Errorf("publish LSM artifact: %w", err)
		}
		published = append(published, f.path)
		paths[f.key] = f.path
	}
	return paths, stats, nil
}
