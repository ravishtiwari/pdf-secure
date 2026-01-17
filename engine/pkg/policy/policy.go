package policy

import (
	"encoding/json"
	"fmt"
	"os"
)

// Policy defines the transformation and security rules for a PDF (V1 schema).
type Policy struct {
	PolicyVersion   string                 `json:"policy_version"`
	Encryption      EncryptionConfig       `json:"encryption"`
	Ack             *AckConfig             `json:"ack,omitempty"`
	Labels          *LabelsConfig          `json:"labels,omitempty"`
	Provenance      *ProvenanceConfig      `json:"provenance,omitempty"`
	TamperDetection *TamperDetectionConfig `json:"tamper_detection,omitempty"`
}

// EncryptionConfig defines encryption settings for the secured PDF.
type EncryptionConfig struct {
	Enabled       bool   `json:"enabled"`
	Mode          string `json:"mode"` // "password" only in V1
	UserPassword  string `json:"user_password"`
	AllowPrint    bool   `json:"allow_print"`
	AllowCopy     bool   `json:"allow_copy"`
	AllowModify   bool   `json:"allow_modify"`
	CryptoProfile string `json:"crypto_profile,omitempty"` // "strong"|"compat"|"legacy", defaults to "strong"
}

// AckConfig defines custodianship acknowledgment settings.
type AckConfig struct {
	Required        bool   `json:"required"`
	Text            string `json:"text"` // "OSS_DEFAULT" in V1
	ViewerDependent bool   `json:"viewer_dependent"`
}

// LabelsConfig defines visible and invisible label settings.
type LabelsConfig struct {
	Mode      string          `json:"mode"` // "visible"|"invisible"|"off"
	Visible   *VisibleLabel   `json:"visible,omitempty"`
	Invisible *InvisibleLabel `json:"invisible,omitempty"`
}

// VisibleLabel defines settings for visible watermark/label overlays.
type VisibleLabel struct {
	Text      string `json:"text"`
	Placement string `json:"placement"`            // "footer"|"header"
	Pages     string `json:"pages"`                // "all"|"first"|"range"
	PageRange string `json:"page_range,omitempty"` // e.g., "1-3,8,10-12"
}

// InvisibleLabel defines settings for invisible metadata markers.
type InvisibleLabel struct {
	Enabled   bool   `json:"enabled"`
	Namespace string `json:"namespace"` // e.g., "com.securepdf.v1"
}

// ProvenanceConfig defines document provenance tracking settings.
type ProvenanceConfig struct {
	Enabled    bool   `json:"enabled"`
	DocumentID string `json:"document_id"` // "auto" or custom string
	CopyID     string `json:"copy_id"`     // "auto" or custom string
}

// TamperDetectionConfig defines tamper detection settings.
type TamperDetectionConfig struct {
	Enabled bool   `json:"enabled"`
	HashAlg string `json:"hash_alg"` // "sha256" only in V1
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

	// Apply defaults
	p.applyDefaults()

	if err := p.Validate(); err != nil {
		return nil, err
	}

	return &p, nil
}

// applyDefaults sets default values for optional fields.
func (p *Policy) applyDefaults() {
	// Default crypto profile to "strong" if not specified
	if p.Encryption.CryptoProfile == "" {
		p.Encryption.CryptoProfile = "strong"
	}

	// Default encryption mode to "password" if not specified but encryption is enabled
	if p.Encryption.Enabled && p.Encryption.Mode == "" {
		p.Encryption.Mode = "password"
	}

	// Default tamper detection hash algorithm
	if p.TamperDetection != nil && p.TamperDetection.Enabled && p.TamperDetection.HashAlg == "" {
		p.TamperDetection.HashAlg = "sha256"
	}

	// Default invisible label namespace
	if p.Labels != nil && p.Labels.Invisible != nil && p.Labels.Invisible.Namespace == "" {
		p.Labels.Invisible.Namespace = "com.securepdf.v1"
	}

	// Default visible label placement and pages
	if p.Labels != nil && p.Labels.Visible != nil {
		if p.Labels.Visible.Placement == "" {
			p.Labels.Visible.Placement = "footer"
		}
		if p.Labels.Visible.Pages == "" {
			p.Labels.Visible.Pages = "all"
		}
	}

	// Default provenance IDs
	if p.Provenance != nil && p.Provenance.Enabled {
		if p.Provenance.DocumentID == "" {
			p.Provenance.DocumentID = "auto"
		}
		if p.Provenance.CopyID == "" {
			p.Provenance.CopyID = "auto"
		}
	}

	// Default ack text
	if p.Ack != nil && p.Ack.Text == "" {
		p.Ack.Text = "OSS_DEFAULT"
	}
}

// Validate checks for required fields and logical consistency in the policy.
// This performs basic validation; comprehensive validation with warnings
// is handled by the validate.go ValidatePolicy function.
func (p *Policy) Validate() error {
	// policy_version is required
	if p.PolicyVersion == "" {
		return fmt.Errorf("policy error: policy_version is required")
	}

	// If encryption is enabled, validate encryption config
	if p.Encryption.Enabled {
		// user_password is required
		if p.Encryption.UserPassword == "" {
			return fmt.Errorf("policy error: encryption.user_password is required when encryption is enabled")
		}

		// mode must be "password" in V1
		if p.Encryption.Mode != "" && p.Encryption.Mode != "password" {
			return fmt.Errorf("policy error: encryption.mode must be 'password' in V1, got '%s'", p.Encryption.Mode)
		}

		// crypto_profile must be valid
		validProfiles := map[string]bool{"strong": true, "compat": true, "legacy": true}
		if p.Encryption.CryptoProfile != "" && !validProfiles[p.Encryption.CryptoProfile] {
			return fmt.Errorf("policy error: encryption.crypto_profile must be 'strong', 'compat', or 'legacy', got '%s'", p.Encryption.CryptoProfile)
		}
	}

	// Validate labels config
	if p.Labels != nil {
		// mode must be valid
		validModes := map[string]bool{"visible": true, "invisible": true, "off": true}
		if p.Labels.Mode != "" && !validModes[p.Labels.Mode] {
			return fmt.Errorf("policy error: labels.mode must be 'visible', 'invisible', or 'off', got '%s'", p.Labels.Mode)
		}

		// If labels mode is visible, visible.text is required
		if p.Labels.Mode == "visible" {
			if p.Labels.Visible == nil || p.Labels.Visible.Text == "" {
				return fmt.Errorf("policy error: labels.visible.text is required when mode is visible")
			}
		}

		// If labels visible pages is range, page_range is required
		if p.Labels.Visible != nil {
			if p.Labels.Visible.Pages == "range" && p.Labels.Visible.PageRange == "" {
				return fmt.Errorf("policy error: labels.visible.page_range is required when pages is range")
			}
		}
	}

	return nil
}
