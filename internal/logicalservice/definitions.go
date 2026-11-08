package logicalservice

import "fmt"

// Definitions holds the flat catalog and rules supplied to dnsextract.
// Rules require match.transports; unsupported fields are errors.
type Definitions struct {
	SchemaVersion uint32    `yaml:"schema_version"`
	Services      []Service `yaml:"services"`
	Rules         []Rule    `yaml:"rules"`
}

// LoadDefinitions strictly loads and validates a complete definitions file.
func LoadDefinitions(path string) (*Definitions, error) {
	var d Definitions
	if err := decodeYAMLFile(path, "logical-service definitions", &d); err != nil {
		return nil, err
	}
	if _, _, err := d.models(); err != nil {
		return nil, fmt.Errorf("validate logical-service definitions %q: %w", path, err)
	}
	return &d, nil
}

func (d *Definitions) models() (*Catalog, *Rules, error) {
	if d == nil {
		return nil, nil, fmt.Errorf("logical-service definitions are required")
	}
	c := &Catalog{SchemaVersion: d.SchemaVersion, Services: d.Services}
	if err := c.validate(); err != nil {
		return nil, nil, err
	}
	r := &Rules{SchemaVersion: d.SchemaVersion, Rules: d.Rules}
	if err := r.validate(c); err != nil {
		return nil, nil, err
	}
	return c, r, nil
}

// Classifier validates and snapshots the definitions into an immutable classifier.
func (d *Definitions) Classifier() (*Classifier, error) {
	c, r, err := d.models()
	if err != nil {
		return nil, err
	}
	return NewClassifier(c, r)
}
