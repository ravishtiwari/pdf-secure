package pdf

import (
	"fmt"

	"securepdf-engine/pkg/policy"
	"securepdf-engine/pkg/receipt"
)

const ossDefaultAckText = "This document is secured with SecurePDF (OSS). The recipient acknowledges custodianship responsibility."

// AckResult holds acknowledgment operation results.
type AckResult struct {
	Success  bool
	Warnings []receipt.Warning
	Error    *receipt.Error
}

// ApplyAcknowledgment embeds custodianship acknowledgment metadata in the PDF.
func ApplyAcknowledgment(pdfPath string, ackConfig *policy.AckConfig) (*AckResult, error) {
	result := &AckResult{
		Success:  false,
		Warnings: []receipt.Warning{},
	}

	if ackConfig == nil || !ackConfig.Required {
		result.Success = true
		return result, nil
	}

	// Resolve ack text
	ackText := ackConfig.Text
	if ackText == "OSS_DEFAULT" || ackText == "" {
		ackText = ossDefaultAckText
	}

	// Emit W003 if viewer_dependent
	if ackConfig.ViewerDependent {
		msg, _ := receipt.WarningMessage(receipt.WarnViewerDependentAck)
		result.Warnings = append(result.Warnings, receipt.Warning{
			Code:    receipt.WarnViewerDependentAck,
			Message: msg,
		})
	}

	metadata := map[string]string{
		"SecurePDF_Acknowledgment":     ackText,
		"SecurePDF_AckRequired":        "true",
		"SecurePDF_AckViewerDependent": fmt.Sprintf("%v", ackConfig.ViewerDependent),
	}

	if err := addMetadata(pdfPath, metadata); err != nil {
		result.Error = &receipt.Error{
			Code:    receipt.ErrLabelFailed,
			Message: fmt.Sprintf("Failed to embed acknowledgment: %v", err),
		}
		return result, err
	}

	result.Success = true
	return result, nil
}
