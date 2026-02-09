package pdf

import (
	"fmt"

	"securepdf-engine/pkg/consts"
	"securepdf-engine/pkg/policy"
	"securepdf-engine/pkg/receipt"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
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
	// We MUST disable ObjectStream writing to ensure the PDF structure remains
	// stable (objects not packed/renumbered) for tamper detection hashing.
	conf := model.NewDefaultConfiguration()
	conf.WriteObjectStream = false
	conf.WriteXRefStream = false // Also disable XRef streams for maximum compatibility/stability

	err := api.AddPropertiesFile(pdfPath, pdfPath, metadata, conf)
	if err != nil {
		return fmt.Errorf("failed to add metadata properties: %w", err)
	}

	return nil
}
