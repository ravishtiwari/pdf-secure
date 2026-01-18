package receipt

import (
	"encoding/json"
	"os"
	"testing"
)

func TestReceiptGoldenFiles(t *testing.T) {
	goldenFiles := []struct {
		name     string
		filepath string
		expectOK bool
	}{
		{"success-minimal", "../../testdata/receipts/success/01-minimal-success.json", true},
		{"success-with-warnings", "../../testdata/receipts/success/03-success-with-warnings.json", true},
		{"failure-policy-invalid", "../../testdata/receipts/error/01-policy-invalid.json", false},
	}

	for _, gf := range goldenFiles {
		t.Run(gf.name, func(t *testing.T) {
			data, err := os.ReadFile(gf.filepath)
			if err != nil {
				t.Fatalf("failed to read golden file: %v", err)
			}

			var receipt Receipt
			if err := json.Unmarshal(data, &receipt); err != nil {
				t.Fatalf("golden file contains invalid JSON: %v", err)
			}

			if receipt.EngineVersion == "" {
				t.Error("engine_version is required")
			}
			if receipt.PolicyVersion == "" {
				t.Error("policy_version is required")
			}
			if receipt.Warnings == nil {
				t.Error("warnings must be non-nil slice")
			}
			if receipt.OK != gf.expectOK {
				t.Errorf("expected ok=%v, got %v", gf.expectOK, receipt.OK)
			}
			if receipt.OK && receipt.Error != nil {
				t.Error("ok=true receipts must have error=nil")
			}
			if !receipt.OK && receipt.Error == nil {
				t.Error("ok=false receipts must have error set")
			}
		})
	}
}
