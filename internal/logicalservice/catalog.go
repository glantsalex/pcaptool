// Copyright © 2026 Alex Glants
// All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package logicalservice loads, validates, and applies logical-service
// classification rules.
package logicalservice

import "fmt"

const schemaVersion = 1

// Catalog is a validated logical-service catalog file. Service IDs are stable
// governance identifiers; the loader can validate their syntax and uniqueness,
// but historical immutability must be enforced through configuration review.
type Catalog struct {
	SchemaVersion uint32    `yaml:"schema_version"`
	Services      []Service `yaml:"services"`

	serviceIDs map[string]struct{}
	validated  bool
}

// Service defines one stable logical-service identity and its display name.
type Service struct {
	ID   string `yaml:"id"`
	Name string `yaml:"name"`
}

// LoadCatalog reads and strictly validates a logical-service catalog YAML file.
func LoadCatalog(path string) (*Catalog, error) {
	var catalog Catalog
	if err := decodeYAMLFile(path, "logical-service catalog", &catalog); err != nil {
		return nil, err
	}
	if err := catalog.validate(); err != nil {
		return nil, fmt.Errorf("validate logical-service catalog %q: %w", path, err)
	}
	return &catalog, nil
}
