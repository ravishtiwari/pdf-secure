package pdf

import (
	"fmt"
	"strings"

	"securepdf-engine/pkg/policy"
	"securepdf-engine/pkg/receipt"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
)

// LabelResult holds label operation results
type LabelResult struct {
	Success        bool
	Warnings       []receipt.Warning
	Error          *receipt.Error
	PagesProcessed int
}

// ApplyVisibleLabel adds visible watermark/label to PDF pages
func ApplyVisibleLabel(pdfPath string, labelConfig *policy.VisibleLabel) (*LabelResult, error) {
	result := &LabelResult{
		Success:  false,
		Warnings: []receipt.Warning{},
	}

	if labelConfig == nil || labelConfig.Text == "" {
		result.Success = true
		return result, nil
	}

	// Build watermark configuration
	wm, err := buildWatermark(labelConfig)
	if err != nil {
		result.Error = &receipt.Error{
			Code:    receipt.ErrLabelFailed,
			Message: fmt.Sprintf("Failed to build watermark: %v", err),
		}
		return result, err
	}

	// Parse page selection
	pages, parseErr := parsePageSelection(labelConfig.Pages, labelConfig.PageRange)
	if parseErr != nil {
		result.Error = &receipt.Error{
			Code:    receipt.ErrLabelFailed,
			Message: fmt.Sprintf("Invalid page selection: %v", parseErr),
			Details: map[string]string{"pages": labelConfig.Pages, "page_range": labelConfig.PageRange},
		}
		return result, parseErr
	}

	// Apply watermark using pdfcpu
	err = api.AddWatermarksFile(pdfPath, pdfPath, pages, wm, nil)
	if err != nil {
		// Check if partial success
		if strings.Contains(err.Error(), "some pages") {
			result.Success = true
			result.Warnings = append(result.Warnings, receipt.Warning{
				Code:    receipt.WarnLabelPartiallyApplied,
				Message: fmt.Sprintf("Label applied to some pages, but not all: %v", err),
			})
		} else {
			result.Error = &receipt.Error{
				Code:    receipt.ErrLabelFailed,
				Message: fmt.Sprintf("Watermark application failed: %v", err),
			}
			return result, err
		}
	} else {
		result.Success = true
	}

	result.PagesProcessed = len(pages)
	return result, nil
}

// buildWatermark creates pdfcpu watermark from label config
func buildWatermark(label *policy.VisibleLabel) (*model.Watermark, error) {
	// Construct description string for pdfcpu
	// Format: "font:Helvetica, points:10, color:0.5 0.5 0.5, op:0.6, pos:bc, off:0 10"

	// Base configuration
	descParts := []string{
		"font:Helvetica",
		"points:10",
		"color:0.5 0.5 0.5", // Gray
		"op:0.6",            // Opacity
		"scale:1 abs",       // Absolute scaling
	}

	// Position
	switch label.Placement {
	case "footer":
		descParts = append(descParts, "pos:bc", "off:0 10") // Bottom Center, offset 10pts up
	case "header":
		descParts = append(descParts, "pos:tc", "off:0 -10") // Top Center, offset 10pts down
	default:
		descParts = append(descParts, "pos:bc", "off:0 10")
	}

	desc := strings.Join(descParts, ", ")

	// Parse using pdfcpu
	// (text, description, onTop, unit)
	return pdfcpu.ParseTextWatermarkDetails(label.Text, desc, true, types.POINTS)
}

// parsePageSelection converts policy page config to page numbers
func parsePageSelection(pages, pageRange string) ([]string, error) {
	switch pages {
	case "all":
		return nil, nil // nil means all pages in pdfcpu
	case "first":
		return []string{"1"}, nil
	case "range":
		if pageRange == "" {
			return nil, fmt.Errorf("page_range required when pages=range")
		}
		return []string{pageRange}, nil
	default:
		return nil, fmt.Errorf("invalid pages value: %s", pages)
	}
}
