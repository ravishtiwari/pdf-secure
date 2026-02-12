package main

import (
	"testing"

	"securepdf-engine/pkg/policy"
	"securepdf-engine/pkg/receipt"
)

func TestE2EAcknowledgmentEmbedded(t *testing.T) {
	inputPath := "../../test-pdfs/sample-input.pdf"

	pol := &policy.Policy{
		PolicyVersion: "1.0",
		Encryption:    policy.EncryptionConfig{Enabled: false},
		Ack: &policy.AckConfig{
			Required:        true,
			Text:            "OSS_DEFAULT",
			ViewerDependent: false,
		},
	}

	outputPath, rec := runSecureWithPolicy(t, inputPath, pol)

	if !rec.OK {
		t.Fatalf("expected receipt OK to be true, got error: %+v", rec.Error)
	}

	// Verify ack metadata is present
	props, err := readProperties(outputPath, "")
	if err != nil {
		t.Fatalf("failed to read properties: %v", err)
	}

	if props["SecurePDF_Acknowledgment"] == "" {
		t.Fatal("expected SecurePDF_Acknowledgment metadata to be present")
	}
	if props["SecurePDF_AckRequired"] != "true" {
		t.Fatalf("expected SecurePDF_AckRequired=true, got: %v", props["SecurePDF_AckRequired"])
	}
}

func TestE2EAcknowledgmentViewerDependentWarning(t *testing.T) {
	inputPath := "../../test-pdfs/sample-input.pdf"

	pol := &policy.Policy{
		PolicyVersion: "1.0",
		Encryption:    policy.EncryptionConfig{Enabled: false},
		Ack: &policy.AckConfig{
			Required:        true,
			Text:            "OSS_DEFAULT",
			ViewerDependent: true,
		},
	}

	_, rec := runSecureWithPolicy(t, inputPath, pol)

	if !rec.OK {
		t.Fatalf("expected receipt OK to be true, got error: %+v", rec.Error)
	}

	// Check for W003 warning
	hasW003 := false
	for _, w := range rec.Warnings {
		if w.Code == receipt.WarnViewerDependentAck {
			hasW003 = true
			break
		}
	}
	if !hasW003 {
		t.Errorf("expected W003 warning for viewer_dependent=true, got warnings: %+v", rec.Warnings)
	}
}

func TestE2EAcknowledgmentWithEncryption(t *testing.T) {
	inputPath := "../../test-pdfs/sample-input.pdf"
	password := "AckEncrypt123!"

	pol := &policy.Policy{
		PolicyVersion: "1.0",
		Encryption: policy.EncryptionConfig{
			Enabled:       true,
			Mode:          "password",
			UserPassword:  password,
			CryptoProfile: "strong",
		},
		Ack: &policy.AckConfig{
			Required:        true,
			Text:            "OSS_DEFAULT",
			ViewerDependent: true,
		},
	}

	outputPath, rec := runSecureWithPolicy(t, inputPath, pol)

	if !rec.OK {
		t.Fatalf("expected receipt OK to be true, got error: %+v", rec.Error)
	}

	// Verify ack survives encryption (accessible with password)
	props, err := readProperties(outputPath, password)
	if err != nil {
		t.Fatalf("failed to read encrypted properties: %v", err)
	}

	if props["SecurePDF_Acknowledgment"] == "" {
		t.Fatal("expected SecurePDF_Acknowledgment metadata to survive encryption")
	}
}
