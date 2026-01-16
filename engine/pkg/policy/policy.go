package policy

import (
	"encoding/json"
	"fmt"
	"os"
)

// Policy defines the transformation and security rules for a PDF.
type Policy struct {
	Password      string `json:"password"`
	VisibleLabel  string `json:"visible_label,omitempty"`
	Invisible     bool   `json:"invisible_label,omitempty"`
	Provenance    bool   `json:"provenance,omitempty"`
	Encryption    string `json:"encryption,omitempty"`     // e.g., "AES-256"
	KeyDerivation string `json:"key_derivation,omitempty"` // e.g., "PBKDF2"
}

// Load reads a policy from a JSON file.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}

	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("failed to parse policy JSON: %w", err)
	}

	if err := p.Validate(); err != nil {
		return nil, err
	}

	return &p, nil
}

// Validate checks for required fields and logical consistency in the policy.
func (p *Policy) Validate() error {
	if p.Password == "" {
		return fmt.Errorf("policy error: password is required")
	}
	return nil
}
