package pdf

import (
	"fmt"

	"securepdf-engine/pkg/consts"
	"securepdf-engine/pkg/policy"
	"securepdf-engine/pkg/receipt"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
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

	// Determine profile (default to objects_only if not specified)
	profile := tdConfig.HashProfile
	if profile == "" {
		profile = consts.HashProfileObjectsOnly
	}

	var contentHash string
	var err error

	switch profile {
	case consts.HashProfileObjectsOnly:
		contentHash, err = HashPDFObjectsExcludingMetadata(pdfPath)
	case consts.HashProfileExternal:
		// Legacy/External: Hash the entire file
		contentHash, err = HashPDFContent(pdfPath)
	default:
		// Fallback to ObjectsOnly
		contentHash, err = HashPDFObjectsExcludingMetadata(pdfPath)
	}

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
		consts.MetadataHashProfile:     profile,
		consts.MetadataTamperDetection: "v1",
	}

	// Uses addMetadata from provenance.go (same package)
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

// VerifyTamperDetection validates the embedded hash in the PDF against the actual content.
// It returns true if valid, false if invalid, and an error for operational failures.
func VerifyTamperDetection(pdfPath string) (bool, error) {
	// 1. Read PDF Context to get Metadata
	// We use ReadContextFile to get the context including XRefTable
	ctx, err := api.ReadContextFile(pdfPath)
	if err != nil {
		return false, fmt.Errorf("failed to read PDF context: %w", err)
	}

	// 2. Extract Metadata
	if ctx.XRefTable.Info == nil {
		return false, fmt.Errorf("no info dictionary found")
	}

	objNr := ctx.XRefTable.Info.ObjectNumber.Value()
	entry, found := ctx.XRefTable.Find(objNr)
	if !found {
		return false, fmt.Errorf("info dictionary object not found")
	}

	infoDict, ok := entry.Object.(types.Dict)
	if !ok {
		return false, fmt.Errorf("info object is not a dictionary")
	}

	// Helper to get string from info dict
	getMeta := func(key string) string {
		if val, ok := infoDict.Find(key); ok {
			if sl, ok := val.(types.StringLiteral); ok {
				s, _ := types.StringLiteralToString(sl)
				return s
			}
			if hl, ok := val.(types.HexLiteral); ok {
				s, _ := types.HexLiteralToString(hl)
				return s
			}
		}
		return ""
	}

	embeddedHash := getMeta(consts.MetadataContentHash)
	embeddedProfile := getMeta(consts.MetadataHashProfile)

	if embeddedHash == "" {
		return false, fmt.Errorf("no embedded content hash found")
	}

	// Default profile if missing (backward compatibility)
	if embeddedProfile == "" {
		embeddedProfile = consts.HashProfileObjectsOnly
	}

	// 3. Re-compute Hash (Self-Verification)
	var computedHash string

	switch embeddedProfile {
	case consts.HashProfileObjectsOnly:
		computedHash, err = HashPDFObjectsExcludingMetadata(pdfPath)
	case consts.HashProfileExternal:
		// Verify external profile
		computedHash, err = HashPDFContent(pdfPath)
	default:
		computedHash, err = HashPDFObjectsExcludingMetadata(pdfPath)
	}

	if err != nil {
		return false, fmt.Errorf("failed to re-compute hash: %w", err)
	}

	// 4. Compare
	if computedHash != embeddedHash {
		// Mismatch
		return false, nil
	}

	return true, nil
}
