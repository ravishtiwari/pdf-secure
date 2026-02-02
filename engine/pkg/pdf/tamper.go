package pdf

import (
	"fmt"

	"securepdf-engine/pkg/consts"
	"securepdf-engine/pkg/policy"
	"securepdf-engine/pkg/receipt"
)

// TamperDetectionResult holds tamper detection operation results.
type TamperDetectionResult struct {
	Success     bool
	Warnings    []receipt.Warning
	Error       *receipt.Error
	ContentHash string
}

// ApplyTamperDetection computes content hash and embeds it in PDF metadata.
func ApplyTamperDetection(pdfPath string, tdConfig *policy.TamperDetectionConfig) (*TamperDetectionResult, error) {
	result := &TamperDetectionResult{
		Success:  false,
		Warnings: []receipt.Warning{},
	}

	if tdConfig == nil || !tdConfig.Enabled {
		result.Success = true
		return result, nil
	}

	if tdConfig.HashAlg != "sha256" {
		result.Error = &receipt.Error{
			Code:    receipt.ErrTamperHashFailed,
			Message: fmt.Sprintf("Unsupported hash algorithm: %s", tdConfig.HashAlg),
			Details: map[string]string{"hash_alg": tdConfig.HashAlg},
		}
		return result, fmt.Errorf("unsupported hash algorithm: %s", tdConfig.HashAlg)
	}

	contentHash, err := HashPDFContent(pdfPath)
	if err != nil {
		result.Error = &receipt.Error{
			Code:    receipt.ErrTamperHashFailed,
			Message: fmt.Sprintf("Failed to compute content hash: %v", err),
		}
		return result, err
	}

	result.ContentHash = contentHash

	metadata := map[string]string{
		consts.MetadataContentHash:     contentHash,
		consts.MetadataHashAlgorithm:   tdConfig.HashAlg,
		consts.MetadataTamperDetection: "v1",
	}

	if err := addMetadata(pdfPath, metadata); err != nil {
		result.Warnings = append(result.Warnings, receipt.Warning{
			Code:    receipt.WarnTamperHashEmbedFailed,
			Message: fmt.Sprintf("Content hash computed but embedding failed: %v", err),
		})
		result.Success = true
		return result, nil
	}

	result.Success = true
	return result, nil
}
