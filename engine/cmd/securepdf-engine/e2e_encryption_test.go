package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"securepdf-engine/pkg/receipt"
)

func TestE2EEncryptionAES256(t *testing.T) {
	tmpDir := t.TempDir()
	inputPDF := filepath.Join(tmpDir, "input.pdf")
	outputPDF := filepath.Join(tmpDir, "output.pdf")
	policyPath := filepath.Join(tmpDir, "policy.json")
	receiptPath := filepath.Join(tmpDir, "receipt.json")

	// Create a simple PDF
	content := "%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n4 0 obj\n<< /Length 13 >>\nstream\nBT /F1 24 Tf 100 700 Td (Hello) Tj ET\nendstream\nendobj\n5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\nxref\n0 6\n0000000000 65535 f\n0000000009 00000 n\n0000000058 00000 n\n0000000115 00000 n\n0000000262 00000 n\n0000000325 00000 n\ntrailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n413\n%%EOF"
	if err := os.WriteFile(inputPDF, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create test PDF: %v", err)
	}

	// Create policy with strong encryption
	policy := map[string]interface{}{
		"policy_version": "1.0",
		"encryption": map[string]interface{}{
			"enabled":        true,
			"user_password":  "securepass",
			"crypto_profile": "strong",
		},
	}
	policyData, _ := json.Marshal(policy)
	os.WriteFile(policyPath, policyData, 0644)

	// Build the engine
	engineBin := filepath.Join(tmpDir, "securepdf-engine")
	cmdBuild := exec.Command("go", "build", "-o", engineBin, ".")
	if out, err := cmdBuild.CombinedOutput(); err != nil {
		t.Fatalf("failed to build engine: %v\n%s", err, out)
	}

	// Run engine
	cmdRun := exec.Command(engineBin, "secure",
		"--in", inputPDF,
		"--out", outputPDF,
		"--policy", policyPath,
		"--receipt", receiptPath)
	if out, err := cmdRun.CombinedOutput(); err != nil {
		t.Fatalf("failed to run engine: %v\n%s", err, out)
	}

	// Verify output PDF exists
	if _, err := os.Stat(outputPDF); os.IsNotExist(err) {
		t.Errorf("output PDF does not exist")
	}

	// Verify receipt
	r, err := receipt.Load(receiptPath)
	if err != nil {
		t.Fatalf("failed to load receipt: %v", err)
	}
	if !r.OK {
		t.Errorf("receipt indicates failure: %v", r.Error)
	}
	if r.OutputSHA256 == "" {
		t.Errorf("receipt missing output hash")
	}
}
