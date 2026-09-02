// Copyright © 2026 Alex Glants
// All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package logicalservice

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var (
	benchmarkResult Result
	benchmarkErr    error
)

func BenchmarkClassifier100KEndpoints(b *testing.B) {
	for _, ruleCount := range []int{100, 500, 1000} {
		b.Run(fmt.Sprintf("%d_rules", ruleCount), func(b *testing.B) {
			classifier := loadBenchmarkClassifier(b, ruleCount)
			endpoints := make([]Endpoint, 100_000)
			for i := range endpoints {
				endpoints[i] = Endpoint{
					SubjectID: fmt.Sprintf("endpoint-%d", i),
					DNS:       "unmatched.example.invalid",
					Protocol:  "tcp",
					DstPort:   443,
				}
			}

			b.ReportAllocs()
			b.ResetTimer()
			b.ReportMetric(float64(len(endpoints)), "endpoints/op")
			for i := 0; i < b.N; i++ {
				benchmarkResult, benchmarkErr = classifier.Classify(context.Background(), endpoints)
				if benchmarkErr != nil {
					b.Fatalf("Classify() error = %v", benchmarkErr)
				}
			}
		})
	}
}

func loadBenchmarkClassifier(b *testing.B, ruleCount int) *Classifier {
	b.Helper()
	var rules strings.Builder
	rules.WriteString("schema_version: 1\nrules:\n")
	for i := 0; i < ruleCount; i++ {
		fmt.Fprintf(
			&rules,
			"  - id: rule_%04d\n    priority: %d\n    service_id: example_service\n    match:\n      dns_exact: [rule-%04d.example.invalid]\n      protocol: tcp\n      any_port: true\n",
			i,
			i,
			i,
		)
	}

	dir := b.TempDir()
	catalogPath := filepath.Join(dir, "catalog.yaml")
	rulesPath := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(catalogPath, []byte(validCatalogYAML), 0o600); err != nil {
		b.Fatalf("write catalog: %v", err)
	}
	if err := os.WriteFile(rulesPath, []byte(rules.String()), 0o600); err != nil {
		b.Fatalf("write rules: %v", err)
	}
	catalog, err := LoadCatalog(catalogPath)
	if err != nil {
		b.Fatalf("LoadCatalog() error = %v", err)
	}
	ruleSet, err := LoadRules(rulesPath, catalog)
	if err != nil {
		b.Fatalf("LoadRules() error = %v", err)
	}
	classifier, err := NewClassifier(catalog, ruleSet)
	if err != nil {
		b.Fatalf("NewClassifier() error = %v", err)
	}
	return classifier
}
