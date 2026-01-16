package receipt

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Receipt represents the result of a SecurePDF transformation.
type Receipt struct {
	ID            string    `json:"id"`
	DocumentID    string    `json:"document_id,omitempty"`
	CopyID        string    `json:"copy_id,omitempty"`
	Timestamp     time.Time `json:"timestamp"`
	EngineVersion string    `json:"engine_version"`
	PolicyVersion string    `json:"policy_version,omitempty"`
	InputHash     string    `json:"input_hash,omitempty"`
	OutputHash    string    `json:"output_hash,omitempty"`
	Status        string    `json:"status"` // "success", "warning", "error"
	Warnings      []string  `json:"warnings,omitempty"`
	Errors        []string  `json:"errors,omitempty"`
}

// Save writes the receipt to a JSON file.
func Save(path string, r *Receipt) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal receipt: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write receipt file: %w", err)
	}

	return nil
}
