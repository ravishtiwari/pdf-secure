package pdf

import (
	"os"
	"path/filepath"
	"testing"

	"securepdf-engine/pkg/policy"
	"securepdf-engine/pkg/receipt"
)

func TestEncryptWithAES256(t *testing.T) {
	// Setup
	tmpDir := t.TempDir()
	inputPath := "../../test-pdfs/sample-input.pdf"
	outputPath := filepath.Join(tmpDir, "output-aes256.pdf")

	// Config
	encConfig := policy.EncryptionConfig{
		Enabled:       true,
		UserPassword:  "password",
		CryptoProfile: "strong",
	}

	// Execute
	result, err := Encrypt(inputPath, outputPath, encConfig)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Verify
	if !result.Success {
		t.Error("Expected Success to be true")
	}
	if result.Error != nil {
		t.Errorf("Expected no error, got: %v", result.Error)
	}

	// Verify file exists
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Error("Output file was not created")
	}
}

func TestEncryptWithAES128(t *testing.T) {
	// Setup
	tmpDir := t.TempDir()
	inputPath := "../../test-pdfs/sample-input.pdf"
	outputPath := filepath.Join(tmpDir, "output-aes128.pdf")

	// Config
	encConfig := policy.EncryptionConfig{
		Enabled:       true,
		UserPassword:  "password",
		CryptoProfile: "compat",
	}

	// Execute
	result, err := Encrypt(inputPath, outputPath, encConfig)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Verify
	if !result.Success {
		t.Error("Expected Success to be true")
	}
}

func TestEncryptWithRC4Legacy(t *testing.T) {
	// Setup
	tmpDir := t.TempDir()
	inputPath := "../../test-pdfs/sample-input.pdf"
	outputPath := filepath.Join(tmpDir, "output-rc4.pdf")

	// Config
	encConfig := policy.EncryptionConfig{
		Enabled:       true,
		UserPassword:  "password",
		CryptoProfile: "legacy",
	}

	// Execute
	result, err := Encrypt(inputPath, outputPath, encConfig)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Verify
	if !result.Success {
		t.Error("Expected Success to be true")
	}

	// Check for warnings
	foundWarning := false
	for _, w := range result.Warnings {
		if w.Code == receipt.WarnWeakCryptoRequested {
			foundWarning = true
			break
		}
	}
	if !foundWarning {
		t.Error("Expected WarnWeakCryptoRequested warning for legacy profile")
	}
}

func TestEncryptWithPermissions(t *testing.T) {
	// Setup
	tmpDir := t.TempDir()
	inputPath := "../../test-pdfs/sample-input.pdf"
	outputPath := filepath.Join(tmpDir, "output-perms.pdf")

	// Config: Disable printing
	encConfig := policy.EncryptionConfig{
		Enabled:      true,
		UserPassword: "password",
		AllowPrint:   false,
		AllowCopy:    true,
	}

	// Execute
	result, err := Encrypt(inputPath, outputPath, encConfig)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Verify
	if !result.Success {
		t.Error("Expected Success to be true")
	}
}

func TestEncryptWithAutoProfile(t *testing.T) {
	// Setup
	tmpDir := t.TempDir()
	inputPath := "../../test-pdfs/sample-input.pdf"
	outputPath := filepath.Join(tmpDir, "output-auto.pdf")

	// Config
	encConfig := policy.EncryptionConfig{
		Enabled:       true,
		UserPassword:  "password",
		CryptoProfile: "auto",
	}

	// Execute
	result, err := Encrypt(inputPath, outputPath, encConfig)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Verify
	if !result.Success {
		t.Error("Expected Success to be true")
	}

	// Should default to strong (AES-256)
	// We can't easily verify the internal pdfcpu config here without inspecting the result details or output file,
	// but success means "auto" was accepted.
}
func TestEncryptDisabled(t *testing.T) {
	// Setup
	tmpDir := t.TempDir()
	inputPath := "../../test-pdfs/sample-input.pdf"
	outputPath := filepath.Join(tmpDir, "output-disabled.pdf")

	// Config
	encConfig := policy.EncryptionConfig{
		Enabled: false,
	}

	// Execute
	result, err := Encrypt(inputPath, outputPath, encConfig)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Verify
	if !result.Success {
		t.Error("Expected Success to be true")
	}

	// File should NOT be created by Encrypt when disabled (it just returns success)
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Error("Output file should not be created when encryption is disabled (processor handles copy)")
	}
}
