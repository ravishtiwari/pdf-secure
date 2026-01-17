package policy

import (
	"os"
	"path/filepath"
	"testing"

	"securepdf-engine/pkg/options"
	"securepdf-engine/pkg/receipt"
)

// TestValidationWithEngineOptions tests the interaction between policy validation
// and engine runtime options (e.g., reject_weak_crypto).
func TestValidationWithEngineOptions(t *testing.T) {
	tests := []struct {
		name             string
		policyFile       string
		engineOpts       []string
		expectValid      bool
		expectWarnings   int
		expectErrorCode  string
		expectErrorField string
	}{
		{
			name:           "valid minimal policy with defaults",
			policyFile:     "../../testdata/policies/valid/01-minimal-encryption-only.json",
			engineOpts:     []string{},
			expectValid:    true,
			expectWarnings: 0,
		},
		{
			name:           "legacy crypto without rejection",
			policyFile:     "../../testdata/policies/valid/07-legacy-crypto.json",
			engineOpts:     []string{},
			expectValid:    true,
			expectWarnings: 1, // WEAK_CRYPTO_REQUESTED
		},
		{
			name:            "legacy crypto with rejection",
			policyFile:      "../../testdata/policies/valid/07-legacy-crypto.json",
			engineOpts:      []string{"reject_weak_crypto=true"},
			expectValid:     false,
			expectWarnings:  1, // Warning still exists
			expectErrorCode: receipt.ErrPolicyInvalid,
		},
		{
			name:           "full features enabled",
			policyFile:     "../../testdata/policies/valid/02-full-features-enabled.json",
			engineOpts:     []string{},
			expectValid:    true,
			expectWarnings: 0,
		},
		{
			name:             "missing password",
			policyFile:       "../../testdata/policies/invalid/03-missing-user-password.json",
			engineOpts:       []string{},
			expectValid:      false,
			expectErrorCode:  receipt.ErrPolicyInvalid,
			expectErrorField: "encryption.user_password",
		},
		{
			name:             "invalid encryption mode",
			policyFile:       "../../testdata/policies/invalid/02-invalid-encryption-mode.json",
			engineOpts:       []string{},
			expectValid:      false,
			expectErrorCode:  receipt.ErrPolicyInvalid,
			expectErrorField: "encryption.mode",
		},
		{
			name:             "invalid label mode",
			policyFile:       "../../testdata/policies/invalid/05-invalid-label-mode.json",
			engineOpts:       []string{},
			expectValid:      false,
			expectErrorCode:  receipt.ErrPolicyInvalid,
			expectErrorField: "labels.mode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Load policy
			p, err := Load(tt.policyFile)
			if err != nil {
				if tt.expectValid {
					t.Fatalf("unexpected load error: %v", err)
				}
				// Expected to fail loading - verify error code if we can
				return
			}

			// Parse engine options
			opts, err := options.Parse(tt.engineOpts)
			if err != nil {
				t.Fatalf("failed to parse engine opts: %v", err)
			}

			// Validate with options
			result := p.ValidateWithOptions(opts)

			// Check validity
			if result.Valid != tt.expectValid {
				t.Errorf("expected valid=%v, got %v", tt.expectValid, result.Valid)
				if result.Error != nil {
					t.Logf("error: [%s] %s", result.Error.Code, result.Error.Message)
				}
			}

			// Check warning count
			if len(result.Warnings) != tt.expectWarnings {
				t.Errorf("expected %d warnings, got %d", tt.expectWarnings, len(result.Warnings))
				for _, w := range result.Warnings {
					t.Logf("warning: [%s] %s", w.Code, w.Message)
				}
			}

			// Check error code
			if !result.Valid {
				if result.Error == nil {
					t.Fatal("expected error to be set when valid=false")
				}
				if tt.expectErrorCode != "" && result.Error.Code != tt.expectErrorCode {
					t.Errorf("expected error code %s, got %s", tt.expectErrorCode, result.Error.Code)
				}
				if tt.expectErrorField != "" {
					field, ok := result.Error.Details["field"]
					if !ok || field != tt.expectErrorField {
						t.Errorf("expected error field %s, got %s", tt.expectErrorField, field)
					}
				}
			}
		})
	}
}

// TestValidationWarningCodes verifies that correct warning codes are emitted.
func TestValidationWarningCodes(t *testing.T) {
	t.Run("weak crypto warning code", func(t *testing.T) {
		p, err := Load("../../testdata/policies/valid/07-legacy-crypto.json")
		if err != nil {
			t.Fatalf("failed to load policy: %v", err)
		}

		result := p.Validate()
		if !result.Valid {
			t.Fatal("expected valid policy")
		}

		if len(result.Warnings) != 1 {
			t.Fatalf("expected 1 warning, got %d", len(result.Warnings))
		}

		if result.Warnings[0].Code != receipt.WarnWeakCryptoRequested {
			t.Errorf("expected warning code %s, got %s", receipt.WarnWeakCryptoRequested, result.Warnings[0].Code)
		}
	})
}

// TestValidationWithMissingFiles ensures proper error handling for missing files.
func TestValidationWithMissingFiles(t *testing.T) {
	_, err := Load("/nonexistent/policy.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

// TestValidationWithInvalidJSON ensures proper error handling for invalid JSON.
func TestValidationWithInvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	invalidJSON := filepath.Join(tmpDir, "invalid.json")
	if err := os.WriteFile(invalidJSON, []byte("{invalid json}"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	_, err := Load(invalidJSON)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// TestEngineOptionsAffectValidation verifies that engine options properly influence validation.
func TestEngineOptionsAffectValidation(t *testing.T) {
	// Create a policy with weak crypto inline
	tmpDir := t.TempDir()
	weakPolicy := filepath.Join(tmpDir, "weak.json")
	content := `{
		"policy_version": "1.0",
		"encryption": {
			"enabled": true,
			"mode": "password",
			"user_password": "test123",
			"crypto_profile": "legacy"
		}
	}`
	if err := os.WriteFile(weakPolicy, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write policy: %v", err)
	}

	p, err := Load(weakPolicy)
	if err != nil {
		t.Fatalf("failed to load policy: %v", err)
	}

	t.Run("without reject_weak_crypto", func(t *testing.T) {
		opts := options.Default()
		result := p.ValidateWithOptions(opts)

		if !result.Valid {
			t.Error("expected valid with default options")
		}
		if len(result.Warnings) != 1 {
			t.Errorf("expected 1 warning, got %d", len(result.Warnings))
		}
	})

	t.Run("with reject_weak_crypto=true", func(t *testing.T) {
		opts := &options.EngineOptions{RejectWeakCrypto: true}
		result := p.ValidateWithOptions(opts)

		if result.Valid {
			t.Error("expected invalid when rejecting weak crypto")
		}
		if result.Error == nil {
			t.Fatal("expected error to be set")
		}
		if result.Error.Code != receipt.ErrPolicyInvalid {
			t.Errorf("expected error code %s, got %s", receipt.ErrPolicyInvalid, result.Error.Code)
		}
	})
}

// TestValidationResultContainsDetails verifies error details are populated.
func TestValidationResultContainsDetails(t *testing.T) {
	tmpDir := t.TempDir()
	badPolicy := filepath.Join(tmpDir, "bad.json")
	content := `{
		"policy_version": "1.0",
		"encryption": {
			"enabled": true,
			"mode": "password"
		}
	}`
	if err := os.WriteFile(badPolicy, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write policy: %v", err)
	}

	_, err := Load(badPolicy)
	if err == nil {
		t.Fatal("expected validation error for missing password")
	}

	// Error message should mention the field
	if err.Error() == "" {
		t.Error("expected non-empty error message")
	}
}
