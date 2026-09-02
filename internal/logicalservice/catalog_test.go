// Copyright © 2026 Alex Glants
// All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package logicalservice

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validCatalogYAML = `
schema_version: 1
services:
  - id: example_service
    name: Example Service
`

func TestLoadCatalog(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{name: "valid", yaml: validCatalogYAML},
		{name: "unsupported schema", yaml: "schema_version: 2\nservices:\n  - id: example_service\n    name: Example\n", wantErr: "unsupported value 2"},
		{name: "missing services", yaml: "schema_version: 1\n", wantErr: "services: field is required"},
		{name: "empty services", yaml: "schema_version: 1\nservices: []\n", wantErr: "must contain at least one"},
		{name: "missing id", yaml: "schema_version: 1\nservices:\n  - name: Example\n", wantErr: "id is required"},
		{name: "duplicate trimmed id", yaml: "schema_version: 1\nservices:\n  - {id: example_service, name: One}\n  - {id: ' example_service ', name: Two}\n", wantErr: "duplicate id"},
		{name: "invalid id", yaml: "schema_version: 1\nservices:\n  - {id: Example-Service, name: Example}\n", wantErr: "must match"},
		{name: "empty name", yaml: "schema_version: 1\nservices:\n  - {id: example_service, name: '   '}\n", wantErr: "name is required"},
		{name: "unknown field", yaml: "schema_version: 1\nservices:\n  - {id: example_service, name: Example, owner: nobody}\n", wantErr: "field owner not found"},
		{name: "multiple documents", yaml: validCatalogYAML + "---\nschema_version: 1\nservices: []\n", wantErr: "multiple YAML documents"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTestFile(t, "catalog.yaml", tt.yaml)
			got, err := LoadCatalog(path)
			if tt.wantErr != "" {
				assertErrorContains(t, err, path, tt.wantErr)
				return
			}
			if err != nil {
				t.Fatalf("LoadCatalog() error = %v", err)
			}
			if got.SchemaVersion != 1 || len(got.Services) != 1 {
				t.Fatalf("LoadCatalog() = %#v", got)
			}
			if got.Services[0].ID != "example_service" || got.Services[0].Name != "Example Service" {
				t.Fatalf("canonical service = %#v", got.Services[0])
			}
		})
	}
}

func writeTestFile(t *testing.T, name, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write test file: %v", err)
	}
	return path
}

func assertErrorContains(t *testing.T, err error, values ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	for _, value := range values {
		if !strings.Contains(err.Error(), value) {
			t.Fatalf("error %q does not contain %q", err, value)
		}
	}
}
