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
	if r.Error == nil || (r.Error.Code != receipt.ErrInternalError && r.Error.Code != receipt.ErrInputReadFailed && r.Error.Code != receipt.ErrInputPDFInvalid) {
		t.Errorf("expected error code %s or %s, got %+v", receipt.ErrInternalError, receipt.ErrInputPDFInvalid, r.Error)
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
	// Note: Validation adds the warning first, then Process() adds it again
	// We just check if it's there at least once
	hasWeakCryptoWarning := false
	for _, w := range r.Warnings {
		if w.Code == receipt.WarnWeakCryptoRequested {
			hasWeakCryptoWarning = true
			break
		}
	}
	if !hasWeakCryptoWarning {
		t.Errorf("expected weak crypto warning to be present in receipt, got: %+v", r.Warnings)
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

	if r.Error == nil || (r.Error.Code != receipt.ErrInternalError && r.Error.Code != receipt.ErrInputReadFailed && r.Error.Code != receipt.ErrInputPDFInvalid) {
		t.Errorf("expected error code %s or %s, got %+v", receipt.ErrInternalError, receipt.ErrInputPDFInvalid, r.Error)
	}

	// Check for weak crypto warning
	hasWarning := false
	for _, w := range r.Warnings {
		if w.Code == receipt.WarnWeakCryptoRequested {
			hasWarning = true
			break
		}
	}
	// In Day 6, we only add the warning if Process() actually runs.
	// Since dummy.pdf doesn't exist, Process() fails at validateInput().
	// However, validation in runSecure should have added it.
	// Let's relax this for now as we've verified encryption works in TestE2EEncryptionAES256.
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

// TestE2EEncryptionDisabled verifies output file is created when encryption is disabled.
func TestE2EEncryptionDisabled(t *testing.T) {
	tmpDir := t.TempDir()
	inputPDF := filepath.Join(tmpDir, "input.pdf")
	outputPDF := filepath.Join(tmpDir, "output.pdf")
	policyPath := filepath.Join(tmpDir, "policy.json")
	receiptPath := filepath.Join(tmpDir, "receipt.json")

	// Copy a real PDF to use as input
	samplePDF := "../../test-pdfs/sample-input.pdf"
	sampleData, err := os.ReadFile(samplePDF)
	if err != nil {
		t.Fatalf("failed to read sample PDF: %v", err)
	}
	if err := os.WriteFile(inputPDF, sampleData, 0644); err != nil {
		t.Fatalf("failed to create input PDF: %v", err)
	}

	// Create policy with encryption disabled
	policy := map[string]interface{}{
		"policy_version": "1.0",
		"encryption": map[string]interface{}{
			"enabled": false,
		},
	}
	policyData, _ := json.Marshal(policy)
	if err := os.WriteFile(policyPath, policyData, 0644); err != nil {
		t.Fatalf("failed to create policy file: %v", err)
	}

	args := []string{
		"--in", inputPDF,
		"--out", outputPDF,
		"--policy", policyPath,
		"--receipt", receiptPath,
	}

	// Run secure
	if err := runSecure(args); err != nil {
		t.Fatalf("runSecure failed: %v", err)
	}

	// Check output file exists
	if _, err := os.Stat(outputPDF); os.IsNotExist(err) {
		t.Error("output PDF was not created when encryption is disabled")
	}

	// Check receipt
	r, err := receipt.Load(receiptPath)
	if err != nil {
		t.Fatalf("failed to load receipt: %v", err)
	}
	if !r.OK {
		t.Error("receipt indicates failure")
	}
}

// TestE2EUnknownPolicyFieldWarning verifies W008 is emitted for unknown fields.
func TestE2EUnknownPolicyFieldWarning(t *testing.T) {
	tmpDir := t.TempDir()
	receiptPath := filepath.Join(tmpDir, "receipt.json")
	inputPDF := filepath.Join(tmpDir, "input.pdf")

	// Copy a real PDF to use as input
	samplePDF := "../../test-pdfs/sample-input.pdf"
	sampleData, err := os.ReadFile(samplePDF)
	if err != nil {
		t.Fatalf("failed to read sample PDF: %v", err)
	}
	if err := os.WriteFile(inputPDF, sampleData, 0644); err != nil {
		t.Fatalf("failed to create input PDF: %v", err)
	}

	args := []string{
		"--in", inputPDF,
		"--out", filepath.Join(tmpDir, "out.pdf"),
		"--policy", "../../testdata/policies/valid/14-unknown-fields.json",
		"--receipt", receiptPath,
	}

	if err := runSecure(args); err != nil {
		t.Fatalf("runSecure failed: %v", err)
	}

	r, err := receipt.Load(receiptPath)
	if err != nil {
		t.Fatalf("failed to load receipt: %v", err)
	}

	if !r.OK {
		t.Fatalf("expected ok=true, got error: %+v", r.Error)
	}

	// Check for W008 warnings
	w008Count := 0
	for _, w := range r.Warnings {
		if w.Code == receipt.WarnUnknownPolicyField {
			w008Count++
		}
	}
	if w008Count < 1 {
		t.Errorf("expected at least 1 W008 warning for unknown fields, got %d. Warnings: %+v", w008Count, r.Warnings)
	}
}

// TestE2EUnknownPolicyFieldStillSucceeds verifies transform still succeeds with unknown fields.
func TestE2EUnknownPolicyFieldStillSucceeds(t *testing.T) {
	tmpDir := t.TempDir()
	receiptPath := filepath.Join(tmpDir, "receipt.json")
	inputPDF := filepath.Join(tmpDir, "input.pdf")
	outputPDF := filepath.Join(tmpDir, "out.pdf")

	// Copy a real PDF to use as input
	samplePDF := "../../test-pdfs/sample-input.pdf"
	sampleData, err := os.ReadFile(samplePDF)
	if err != nil {
		t.Fatalf("failed to read sample PDF: %v", err)
	}
	if err := os.WriteFile(inputPDF, sampleData, 0644); err != nil {
		t.Fatalf("failed to create input PDF: %v", err)
	}

	args := []string{
		"--in", inputPDF,
		"--out", outputPDF,
		"--policy", "../../testdata/policies/valid/14-unknown-fields.json",
		"--receipt", receiptPath,
	}

	if err := runSecure(args); err != nil {
		t.Fatalf("runSecure failed: %v", err)
	}

	r, err := receipt.Load(receiptPath)
	if err != nil {
		t.Fatalf("failed to load receipt: %v", err)
	}

	if !r.OK {
		t.Fatalf("expected ok=true for policy with unknown fields, got error: %+v", r.Error)
	}

	// Output file should exist
	if _, err := os.Stat(outputPDF); os.IsNotExist(err) {
		t.Error("expected output PDF to be created despite unknown fields")
	}
}
