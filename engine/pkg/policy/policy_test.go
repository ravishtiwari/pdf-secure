package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadValidPolicies verifies that all valid policy fixtures load successfully
func TestLoadValidPolicies(t *testing.T) {
	validDir := "../../testdata/policies/valid"
	entries, err := os.ReadDir(validDir)
	if err != nil {
		t.Fatalf("failed to read valid policies directory: %v", err)
	}

	if len(entries) == 0 {
		t.Fatal("no valid policy fixtures found")
	}

	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		t.Run(entry.Name(), func(t *testing.T) {
			path := filepath.Join(validDir, entry.Name())
			p, err := Load(path)
			if err != nil {
				t.Fatalf("expected valid policy to load, got error: %v", err)
			}

			// Verify required fields
			if p.PolicyVersion != "1.0" {
				t.Errorf("expected policy_version=1.0, got %s", p.PolicyVersion)
			}

			// Verify encryption defaults are applied
			if p.Encryption.Enabled && p.Encryption.CryptoProfile == "" {
				t.Error("expected crypto_profile to have default value")
			}
		})
	}
}

// TestLoadInvalidPolicies verifies that all invalid policy fixtures fail to load
func TestLoadInvalidPolicies(t *testing.T) {
	invalidDir := "../../testdata/policies/invalid"
	entries, err := os.ReadDir(invalidDir)
	if err != nil {
		t.Fatalf("failed to read invalid policies directory: %v", err)
	}

	if len(entries) == 0 {
		t.Fatal("no invalid policy fixtures found")
	}

	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		t.Run(entry.Name(), func(t *testing.T) {
			path := filepath.Join(invalidDir, entry.Name())
			_, err := Load(path)
			if err == nil {
				t.Fatalf("expected invalid policy to fail, but it loaded successfully")
			}
			// Log the error for debugging
			t.Logf("correctly rejected with error: %v", err)
		})
	}
}

// TestPolicyDefaults verifies that optional fields get default values
func TestPolicyDefaults(t *testing.T) {
	// Create minimal policy JSON
	minimalJSON := `{
		"policy_version": "1.0",
		"encryption": {
			"enabled": true,
			"mode": "password",
			"user_password": "test123"
		}
	}`

	tmpFile := filepath.Join(t.TempDir(), "minimal.json")
	if err := os.WriteFile(tmpFile, []byte(minimalJSON), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	p, err := Load(tmpFile)
	if err != nil {
		t.Fatalf("failed to load minimal policy: %v", err)
	}

	// Verify defaults
	if p.Encryption.CryptoProfile != "strong" {
		t.Errorf("expected crypto_profile default 'strong', got '%s'", p.Encryption.CryptoProfile)
	}
}

// TestPolicyJSONRoundTrip verifies JSON marshal/unmarshal preserves all fields
func TestPolicyJSONRoundTrip(t *testing.T) {
	original := &Policy{
		PolicyVersion: "1.0",
		Encryption: EncryptionConfig{
			Enabled:       true,
			Mode:          "password",
			UserPassword:  "test123",
			AllowPrint:    true,
			AllowCopy:     false,
			AllowModify:   false,
			CryptoProfile: "strong",
		},
		Ack: &AckConfig{
			Required:        true,
			Text:            "OSS_DEFAULT",
			ViewerDependent: true,
		},
		Labels: &LabelsConfig{
			Mode: "visible",
			Visible: &VisibleLabel{
				Text:      "CONFIDENTIAL",
				Placement: "footer",
				Pages:     "all",
			},
		},
		Provenance: &ProvenanceConfig{
			Enabled:    true,
			DocumentID: "doc-123",
			CopyID:     "copy-456",
		},
		TamperDetection: &TamperDetectionConfig{
			Enabled: true,
			HashAlg: "sha256",
		},
	}

	// Marshal to JSON
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal policy: %v", err)
	}

	// Unmarshal back
	var restored Policy
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("failed to unmarshal policy: %v", err)
	}

	// Verify key fields
	if restored.PolicyVersion != original.PolicyVersion {
		t.Errorf("policy_version mismatch: got %s, want %s", restored.PolicyVersion, original.PolicyVersion)
	}
	if restored.Encryption.UserPassword != original.Encryption.UserPassword {
		t.Errorf("encryption.user_password mismatch")
	}
	if restored.Ack == nil || restored.Ack.Text != original.Ack.Text {
		t.Errorf("ack.text mismatch")
	}
	if restored.Labels == nil || restored.Labels.Visible == nil || restored.Labels.Visible.Text != original.Labels.Visible.Text {
		t.Errorf("labels.visible.text mismatch")
	}
	if restored.Provenance == nil || restored.Provenance.DocumentID != original.Provenance.DocumentID {
		t.Errorf("provenance.document_id mismatch")
	}
	if restored.TamperDetection == nil || restored.TamperDetection.HashAlg != original.TamperDetection.HashAlg {
		t.Errorf("tamper_detection.hash_alg mismatch")
	}
}

// TestUnknownFieldsIgnored verifies that unknown JSON fields don't cause errors (forward compatibility)
func TestUnknownFieldsIgnored(t *testing.T) {
	jsonWithUnknown := `{
		"policy_version": "1.0",
		"encryption": {
			"enabled": true,
			"mode": "password",
			"user_password": "test123"
		},
		"future_feature": {
			"enabled": true,
			"some_setting": "value"
		}
	}`

	tmpFile := filepath.Join(t.TempDir(), "unknown.json")
	if err := os.WriteFile(tmpFile, []byte(jsonWithUnknown), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	p, err := Load(tmpFile)
	if err != nil {
		t.Fatalf("policy with unknown fields should load: %v", err)
	}

	if p.PolicyVersion != "1.0" {
		t.Errorf("expected policy_version=1.0, got %s", p.PolicyVersion)
	}
}

// TestLegacyPolicyCompatibility verifies legacy policy format is accepted.
func TestLegacyPolicyCompatibility(t *testing.T) {
	legacyJSON := `{
		"password": "legacy-pass",
		"visible_label": "CONFIDENTIAL",
		"provenance": true,
		"encryption": "aes256"
	}`

	tmpFile := filepath.Join(t.TempDir(), "legacy.json")
	if err := os.WriteFile(tmpFile, []byte(legacyJSON), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	p, err := Load(tmpFile)
	if err != nil {
		t.Fatalf("legacy policy should load: %v", err)
	}

	if p.PolicyVersion != "1.0" {
		t.Errorf("expected policy_version=1.0, got %s", p.PolicyVersion)
	}
	if !p.Encryption.Enabled || p.Encryption.UserPassword != "legacy-pass" {
		t.Error("expected legacy password to map to encryption.user_password")
	}
	if p.Labels == nil || p.Labels.Mode != "visible" || p.Labels.Visible == nil || p.Labels.Visible.Text != "CONFIDENTIAL" {
		t.Error("expected legacy visible_label to map to labels.visible")
	}
	if p.Provenance == nil || !p.Provenance.Enabled {
		t.Error("expected legacy provenance=true to enable provenance")
	}
}

// TestUnknownFieldsGenerateW008Warning verifies unknown fields generate W008 warnings.
func TestUnknownFieldsGenerateW008Warning(t *testing.T) {
	jsonWithUnknown := `{
		"policy_version": "1.0",
		"encryption": {
			"enabled": false
		},
		"future_feature": true,
		"experimental_mode": "test"
	}`

	tmpFile := filepath.Join(t.TempDir(), "unknown-w008.json")
	if err := os.WriteFile(tmpFile, []byte(jsonWithUnknown), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	p, res, err := LoadWithOptions(tmpFile, nil)
	if err != nil {
		t.Fatalf("policy with unknown fields should load: %v", err)
	}

	if p.PolicyVersion != "1.0" {
		t.Errorf("expected policy_version=1.0, got %s", p.PolicyVersion)
	}

	// Check for W008 warnings
	if res == nil {
		t.Fatal("expected validation result")
	}

	w008Count := 0
	for _, w := range res.Warnings {
		if w.Code == "W008" {
			w008Count++
			t.Logf("W008 warning: %s", w.Message)
		}
	}

	if w008Count < 2 {
		t.Errorf("expected at least 2 W008 warnings (future_feature, experimental_mode), got %d. Warnings: %+v", w008Count, res.Warnings)
	}
}

// TestSpecificValidFixtures verifies specific fixture behaviors
func TestSpecificValidFixtures(t *testing.T) {
	t.Run("02-full-features-enabled", func(t *testing.T) {
		p, err := Load("../../testdata/policies/valid/02-full-features-enabled.json")
		if err != nil {
			t.Fatalf("failed to load: %v", err)
		}

		// Verify all features are present
		if p.Ack == nil {
			t.Error("expected ack config to be present")
		}
		if p.Labels == nil {
			t.Error("expected labels config to be present")
		}
		if p.Provenance == nil {
			t.Error("expected provenance config to be present")
		}
		if p.TamperDetection == nil {
			t.Error("expected tamper_detection config to be present")
		}
	})

	t.Run("07-legacy-crypto", func(t *testing.T) {
		p, err := Load("../../testdata/policies/valid/07-legacy-crypto.json")
		if err != nil {
			t.Fatalf("failed to load: %v", err)
		}

		if p.Encryption.CryptoProfile != "legacy" {
			t.Errorf("expected crypto_profile=legacy, got %s", p.Encryption.CryptoProfile)
		}
	})

	t.Run("08-visible-label-page-range", func(t *testing.T) {
		p, err := Load("../../testdata/policies/valid/08-visible-label-page-range.json")
		if err != nil {
			t.Fatalf("failed to load: %v", err)
		}

		if p.Labels == nil || p.Labels.Visible == nil {
			t.Fatal("expected visible labels config")
		}
		if p.Labels.Visible.Pages != "range" {
			t.Errorf("expected pages=range, got %s", p.Labels.Visible.Pages)
		}
		if p.Labels.Visible.PageRange != "1-3,5,8-10" {
			t.Errorf("expected page_range='1-3,5,8-10', got %s", p.Labels.Visible.PageRange)
		}
	})
}
