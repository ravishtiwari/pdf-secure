package policy

import (
	"testing"

	"securepdf-engine/pkg/options"
	"securepdf-engine/pkg/receipt"
)

func TestValidateWithOptionsFixtures(t *testing.T) {
	tests := []struct {
		name            string
		policyFile      string
		engineOpts      []string
		expectValid     bool
		expectWarning   string
		expectErrorCode string
	}{
		{
			name:          "legacy crypto without rejection",
			policyFile:    "../../testdata/policies/valid/07-legacy-crypto.json",
			engineOpts:    []string{},
			expectValid:   true,
			expectWarning: receipt.WarnWeakCryptoRequested,
		},
		{
			name:            "legacy crypto with rejection",
			policyFile:      "../../testdata/policies/valid/07-legacy-crypto.json",
			engineOpts:      []string{"reject_weak_crypto=true"},
			expectValid:     false,
			expectWarning:   receipt.WarnWeakCryptoRequested,
			expectErrorCode: receipt.ErrPolicyInvalid,
		},
		{
			name:            "missing password",
			policyFile:      "../../testdata/policies/invalid/03-missing-user-password.json",
			engineOpts:      []string{},
			expectValid:     false,
			expectErrorCode: receipt.ErrPolicyInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts, err := options.Parse(tt.engineOpts)
			if err != nil {
				t.Fatalf("unexpected options parse error: %v", err)
			}

			_, res, err := LoadWithOptions(tt.policyFile, opts)
			if err != nil {
				t.Fatalf("unexpected load error: %v", err)
			}

			if res.Valid != tt.expectValid {
				t.Errorf("expected valid=%v, got %v", tt.expectValid, res.Valid)
			}

			if tt.expectWarning != "" {
				found := false
				for _, w := range res.Warnings {
					if w.Code == tt.expectWarning {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected warning %s to be present", tt.expectWarning)
				}
			}

			if !res.Valid {
				if res.Error == nil || res.Error.Code != tt.expectErrorCode {
					t.Errorf("expected error code %s, got %+v", tt.expectErrorCode, res.Error)
				}
			}
		})
	}
}
