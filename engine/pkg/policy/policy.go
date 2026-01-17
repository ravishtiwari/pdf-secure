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

	var policy Policy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("failed to parse policy JSON: %w", err)
	}

	// Apply defaults
	policy.applyDefaults()

	validation := policy.Validate()
	if !validation.Valid {
		if validation.Error != nil {
			return nil, fmt.Errorf("policy invalid (%s): %s", validation.Error.Code, validation.Error.Message)
		}
		return nil, fmt.Errorf("policy invalid")
	}

	return &policy, nil
}

// applyDefaults sets default values for optional fields.
func (policy *Policy) applyDefaults() {
	// Default crypto profile to "strong" if not specified
	policy.Encryption.CryptoProfile = defaultCryptoProfile(policy.Encryption)

	// Default encryption mode to "password" if not specified but encryption is enabled
	if policy.Encryption.Enabled {
		policy.Encryption.Mode = defaultEncryptionMode(policy.Encryption)
	}

	// Default tamper detection hash algorithm
	if policy.TamperDetection != nil && policy.TamperDetection.Enabled && policy.TamperDetection.HashAlg == "" {
		policy.TamperDetection.HashAlg = defaultTamperHashAlg(policy.TamperDetection)
	}

	// Default labels mode
	if policy.Labels != nil && policy.Labels.Mode == "" {
		policy.Labels.Mode = defaultLabelsMode(policy.Labels)
	}

	// Default invisible label namespace
	if policy.Labels != nil && policy.Labels.Invisible != nil && policy.Labels.Invisible.Namespace == "" {
		policy.Labels.Invisible.Namespace = defaultInvisibleNamespace(policy.Labels.Invisible)
	}

	// Default visible label placement and pages
	if policy.Labels != nil && policy.Labels.Visible != nil {
		if policy.Labels.Visible.Placement == "" {
			policy.Labels.Visible.Placement = defaultVisiblePlacement(policy.Labels.Visible)
		}
		if policy.Labels.Visible.Pages == "" {
			policy.Labels.Visible.Pages = defaultVisiblePages(policy.Labels.Visible)
		}
	}

	// Default provenance IDs
	if policy.Provenance != nil && policy.Provenance.Enabled {
		if policy.Provenance.DocumentID == "" {
			policy.Provenance.DocumentID = defaultProvenanceID(policy.Provenance.DocumentID)
		}
		if policy.Provenance.CopyID == "" {
			policy.Provenance.CopyID = defaultProvenanceID(policy.Provenance.CopyID)
		}
	}

	// Default ack text
	if policy.Ack != nil && policy.Ack.Text == "" {
		policy.Ack.Text = defaultAckText(policy.Ack)
	}
}
