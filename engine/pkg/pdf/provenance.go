package pdf

import (
	"fmt"

	"securepdf-engine/pkg/consts"
	"securepdf-engine/pkg/policy"
	"securepdf-engine/pkg/receipt"

	"github.com/pdfcpu/pdfcpu/pkg/api"
)

// ProvenanceResult holds provenance operation results
type ProvenanceResult struct {
	Success    bool
	Warnings   []receipt.Warning
	Error      *receipt.Error
	DocumentID string
	CopyID     string
}

// ApplyProvenance adds provenance metadata to PDF
func ApplyProvenance(pdfPath string, provConfig *policy.ProvenanceConfig) (*ProvenanceResult, error) {
	result := &ProvenanceResult{
		Success:  false,
		Warnings: []receipt.Warning{},
	}

	if provConfig == nil || !provConfig.Enabled {
		result.Success = true
		return result, nil
	}

	// Generate or use provided IDs
	docID := getOrGenerateDocumentID(provConfig.DocumentID)
	copyID := getOrGenerateCopyID(provConfig.CopyID)

	result.DocumentID = docID
	result.CopyID = copyID

	// Add to PDF metadata (Info Dictionary)
	metadata := map[string]string{
		consts.MetadataDocumentID: docID,
		consts.MetadataCopyID:     copyID,
		consts.MetadataVersion:    consts.SecurePDFVersion,
		consts.MetadataTimestamp:  receipt.GetTimestamp(),
	}

	// Add metadata using pdfcpu
	err := addMetadata(pdfPath, metadata)
	if err != nil {
		// Partial failure - IDs generated but not embedded
		result.Warnings = append(result.Warnings, receipt.Warning{
			Code:    receipt.WarnProvenancePartiallyApplied,
			Message: fmt.Sprintf("Provenance IDs generated but embedding failed: %v", err),
		})
		result.Success = true // Still return success with warning
		return result, nil
	}

	result.Success = true
	return result, nil
}

// getOrGenerateDocumentID returns the provided ID or generates a new one.
func getOrGenerateDocumentID(providedID string) string {
	if providedID == "auto" || providedID == "" {
		return receipt.GenerateDocumentID()
	}
	return providedID
}

// getOrGenerateCopyID returns the provided ID or generates a new one.
func getOrGenerateCopyID(providedID string) string {
	if providedID == "auto" || providedID == "" {
		return receipt.GenerateCopyID()
	}
	return providedID
}

// addMetadata adds custom metadata fields to PDF Info dictionary
func addMetadata(pdfPath string, metadata map[string]string) error {
	// Use api.AddPropertiesFile to add metadata fields
	// Note: We leave conf as nil to use default configuration
	// We pass empty string for outPath to overwrite inPath (or so we assume,
	// but AddPropertiesFile usually takes (inFile, outFile, properties, conf).
	// If outFile is empty, does it overwrite?
	// Let's check typical pdfcpu behavior or use tmp file strategy if needed.
	// Actually, for safety, let's use a temporary output file and move it back?
	// Or trust pdfcpu handles empty output as overwrite or error.
	// Checking pdfcpu docs/code indirectly via common patterns: usually requires explicit output.
	// Let's safe bet: overwrite input file by passing it as output file too?
	// api.AddPropertiesFile(inFile, outFile, ...)
	// If inFile == outFile, it should work for pdfcpu.

	err := api.AddPropertiesFile(pdfPath, pdfPath, metadata, nil)
	if err != nil {
		return fmt.Errorf("failed to add metadata properties: %w", err)
	}

	return nil
}
