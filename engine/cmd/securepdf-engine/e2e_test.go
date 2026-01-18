package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"securepdf-engine/pkg/receipt"
)

// =============================================================================
// End-to-End Tests for CLI Workflow
// =============================================================================
//
// These tests verify the complete CLI workflow including:
// 1. Flag parsing
// 2. Policy loading and validation
// 3. Engine options handling
// 4. Receipt generation
// 5. Error handling and exit behavior

// TestE2EValidPolicyCreatesReceipt verifies that a valid policy produces a receipt.
func TestE2EValidPolicyCreatesReceipt(t *testing.T) {
	tmpDir := t.TempDir()
	receiptPath := filepath.Join(tmpDir, "receipt.json")

	args := []string{
		"--in", "dummy.pdf",
		"--out", filepath.Join(tmpDir, "out.pdf"),
		"--policy", "../../testdata/policies/valid/01-minimal-encryption-only.json",
		"--receipt", receiptPath,
	}

	// Note: runSecure returns error because pipeline is stubbed
	err := runSecure(args)

	if err == nil {
		t.Error("expected error for stubbed transformation")
	}

	// Receipt should be created
	if _, err := os.Stat(receiptPath); os.IsNotExist(err) {
		t.Fatal("receipt file was not created")
	}

	// Load and verify receipt
	r, err := receipt.Load(receiptPath)
	if err != nil {
		t.Fatalf("failed to load receipt: %v", err)
	}

	if r.EngineVersion == "" {
		t.Error("expected engine_version to be set")
	}
	if r.PolicyVersion != "1.0" {
		t.Errorf("expected policy_version=1.0, got %s", r.PolicyVersion)
	}
	if r.OK {
		t.Error("expected ok=false for stubbed transformation")
	}
	if r.Error == nil || r.Error.Code != receipt.ErrInternalError {
		t.Errorf("expected error code %s, got %+v", receipt.ErrInternalError, r.Error)
	}
}

// TestE2EInvalidPolicyCreatesErrorReceipt verifies invalid policies produce error receipts.
func TestE2EInvalidPolicyCreatesErrorReceipt(t *testing.T) {
	tmpDir := t.TempDir()
	receiptPath := filepath.Join(tmpDir, "receipt.json")

	args := []string{
		"--in", "dummy.pdf",
		"--out", filepath.Join(tmpDir, "out.pdf"),
		"--policy", "../../testdata/policies/invalid/03-missing-user-password.json",
		"--receipt", receiptPath,
	}

	err := runSecure(args)
	if err == nil {
		t.Error("expected error for invalid policy")
	}

	// Receipt should still be created
	if _, err := os.Stat(receiptPath); os.IsNotExist(err) {
		t.Fatal("receipt file was not created for invalid policy")
	}

	// Load and verify error receipt
	r, err := receipt.Load(receiptPath)
	if err != nil {
		t.Fatalf("failed to load receipt: %v", err)
	}

	if r.OK {
		t.Error("expected ok=false for invalid policy")
	}
	if r.Error == nil {
		t.Fatal("expected error to be set")
	}
	if r.Error.Code != receipt.ErrPolicyInvalid {
		t.Errorf("expected error code %s, got %s", receipt.ErrPolicyInvalid, r.Error.Code)
	}
}

// TestE2EWeakCryptoWithRejection verifies reject_weak_crypto engine option.
func TestE2EWeakCryptoWithRejection(t *testing.T) {
	tmpDir := t.TempDir()
	receiptPath := filepath.Join(tmpDir, "receipt.json")

	args := []string{
		"--in", "dummy.pdf",
		"--out", filepath.Join(tmpDir, "out.pdf"),
		"--policy", "../../testdata/policies/valid/07-legacy-crypto.json",
		"--receipt", receiptPath,
		"--engine-opt", "reject_weak_crypto=true",
	}

	err := runSecure(args)
	if err == nil {
		t.Error("expected error when rejecting weak crypto")
	}

	// Receipt should be created with error
	r, err := receipt.Load(receiptPath)
	if err != nil {
		t.Fatalf("failed to load receipt: %v", err)
	}

	if r.OK {
		t.Error("expected ok=false when rejecting weak crypto")
	}
	if r.Error == nil {
		t.Fatal("expected error to be set")
	}

	// Should have the weak crypto warning in the receipt
	hasWeakCryptoWarning := false
	for _, w := range r.Warnings {
		if w.Code == receipt.WarnWeakCryptoRequested {
			hasWeakCryptoWarning = true
			break
		}
	}
	if !hasWeakCryptoWarning {
		t.Error("expected weak crypto warning to be present in receipt")
	}
}

// TestE2EWeakCryptoWithoutRejection verifies weak crypto is allowed by default.
func TestE2EWeakCryptoWithoutRejection(t *testing.T) {
	tmpDir := t.TempDir()
	receiptPath := filepath.Join(tmpDir, "receipt.json")

	args := []string{
		"--in", "dummy.pdf",
		"--out", filepath.Join(tmpDir, "out.pdf"),
		"--policy", "../../testdata/policies/valid/07-legacy-crypto.json",
		"--receipt", receiptPath,
	}

	// Should return stub error (with warning)
	err := runSecure(args)
	if err == nil {
		t.Error("expected error for stubbed transformation")
	}

	r, err := receipt.Load(receiptPath)
	if err != nil {
		t.Fatalf("failed to load receipt: %v", err)
	}

	if r.Error == nil || r.Error.Code != receipt.ErrInternalError {
		t.Errorf("expected error code %s, got %+v", receipt.ErrInternalError, r.Error)
	}

	// Check for weak crypto warning
	hasWarning := false
	for _, w := range r.Warnings {
		if w.Code == receipt.WarnWeakCryptoRequested {
			hasWarning = true
			break
		}
	}
	if !hasWarning {
		t.Error("expected weak crypto warning to be present")
	}
}

// TestE2EMissingFlags verifies proper error for missing required flags.
func TestE2EMissingFlags(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		missingFlag string
	}{
		{
			name:        "missing --in",
			args:        []string{"--out", "out.pdf", "--policy", "p.json", "--receipt", "r.json"},
			missingFlag: "--in",
		},
		{
			name:        "missing --out",
			args:        []string{"--in", "in.pdf", "--policy", "p.json", "--receipt", "r.json"},
			missingFlag: "--out",
		},
		{
			name:        "missing --policy",
			args:        []string{"--in", "in.pdf", "--out", "out.pdf", "--receipt", "r.json"},
			missingFlag: "--policy",
		},
		{
			name:        "missing --receipt",
			args:        []string{"--in", "in.pdf", "--out", "out.pdf", "--policy", "p.json"},
			missingFlag: "--receipt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runSecure(tt.args)
			if err == nil {
				t.Error("expected error for missing flag")
			}
		})
	}
}

// TestE2EInvalidEngineOpt verifies proper error for invalid engine options.
func TestE2EInvalidEngineOpt(t *testing.T) {
	tmpDir := t.TempDir()

	args := []string{
		"--in", "dummy.pdf",
		"--out", filepath.Join(tmpDir, "out.pdf"),
		"--policy", "../../testdata/policies/valid/01-minimal-encryption-only.json",
		"--receipt", filepath.Join(tmpDir, "receipt.json"),
		"--engine-opt", "invalid_format_no_equals",
	}

	err := runSecure(args)
	if err == nil {
		t.Error("expected error for invalid engine-opt format")
	}
}

// TestE2EMultipleEngineOpts verifies multiple engine options can be passed.
func TestE2EMultipleEngineOpts(t *testing.T) {
	tmpDir := t.TempDir()
	receiptPath := filepath.Join(tmpDir, "receipt.json")

	args := []string{
		"--in", "dummy.pdf",
		"--out", filepath.Join(tmpDir, "out.pdf"),
		"--policy", "../../testdata/policies/valid/01-minimal-encryption-only.json",
		"--receipt", receiptPath,
		"--engine-opt", "timeout_ms=30000",
		"--engine-opt", "max_input_mb=100",
	}

	err := runSecure(args)
	if err != nil {
		t.Logf("runSecure returned: %v", err)
	}

	// Verify receipt was created
	if _, err := os.Stat(receiptPath); os.IsNotExist(err) {
		t.Fatal("receipt file was not created")
	}
}

// TestE2EMissingPolicyFile verifies proper handling of missing policy file.
func TestE2EMissingPolicyFile(t *testing.T) {
	tmpDir := t.TempDir()
	receiptPath := filepath.Join(tmpDir, "receipt.json")

	args := []string{
		"--in", "dummy.pdf",
		"--out", filepath.Join(tmpDir, "out.pdf"),
		"--policy", "/nonexistent/policy.json",
		"--receipt", receiptPath,
	}

	err := runSecure(args)
	if err == nil {
		t.Error("expected error for missing policy file")
	}

	// Receipt should still be created with error
	if _, err := os.Stat(receiptPath); os.IsNotExist(err) {
		t.Fatal("receipt file was not created for missing policy")
	}

	r, err := receipt.Load(receiptPath)
	if err != nil {
		t.Fatalf("failed to load receipt: %v", err)
	}

	if r.OK {
		t.Error("expected ok=false for missing policy file")
	}
}

// TestE2EReceiptSchemaCompliance verifies receipt matches V1 schema.
func TestE2EReceiptSchemaCompliance(t *testing.T) {
	tmpDir := t.TempDir()
	receiptPath := filepath.Join(tmpDir, "receipt.json")

	args := []string{
		"--in", "dummy.pdf",
		"--out", filepath.Join(tmpDir, "out.pdf"),
		"--policy", "../../testdata/policies/valid/02-full-features-enabled.json",
		"--receipt", receiptPath,
	}

	_ = runSecure(args)

	// Load raw JSON to verify schema
	data, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatalf("failed to read receipt: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("receipt is not valid JSON: %v", err)
	}

	// Required fields per V1 schema
	requiredFields := []string{
		"ok",
		"engine_version",
		"policy_version",
		"warnings",
	}

	for _, field := range requiredFields {
		if _, ok := raw[field]; !ok {
			t.Errorf("required field %q missing from receipt", field)
		}
	}

	// Warnings must be an array (not null)
	warnings, ok := raw["warnings"]
	if !ok {
		t.Fatal("warnings field missing")
	}
	if _, ok := warnings.([]interface{}); !ok {
		t.Error("warnings must be an array, not null")
	}
}

// TestE2ELegacyPolicyFormat verifies legacy policy format is accepted.
func TestE2ELegacyPolicyFormat(t *testing.T) {
	tmpDir := t.TempDir()
	receiptPath := filepath.Join(tmpDir, "receipt.json")

	// Create a legacy format policy
	legacyPolicy := filepath.Join(tmpDir, "legacy.json")
	content := `{
		"password": "test123",
		"visible_label": "CONFIDENTIAL"
	}`
	if err := os.WriteFile(legacyPolicy, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write legacy policy: %v", err)
	}

	args := []string{
		"--in", "dummy.pdf",
		"--out", filepath.Join(tmpDir, "out.pdf"),
		"--policy", legacyPolicy,
		"--receipt", receiptPath,
	}

	err := runSecure(args)
	if err != nil {
		t.Logf("runSecure returned: %v", err)
	}

	// Verify receipt was created
	r, err := receipt.Load(receiptPath)
	if err != nil {
		t.Fatalf("failed to load receipt: %v", err)
	}

	// Legacy policy should be converted to 1.0
	if r.PolicyVersion != "1.0" {
		t.Errorf("expected policy_version=1.0 for legacy format, got %s", r.PolicyVersion)
	}
}
