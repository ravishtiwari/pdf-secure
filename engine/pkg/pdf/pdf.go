// Package pdf provides PDF processing capabilities for SecurePDF.
// It handles the complete transformation pipeline: encryption, labels, provenance,
// and tamper detection.
package pdf

import (
	"fmt"
	"io"
	"os"

	"securepdf-engine/pkg/consts"
	"securepdf-engine/pkg/policy"
	"securepdf-engine/pkg/receipt"
)

// Processor handles PDF transformations according to a policy.
type Processor struct {
	policy     *policy.Policy
	inputPath  string
	outputPath string
}

// NewProcessor creates a new PDF processor.
func NewProcessor(pol *policy.Policy, inputPath, outputPath string) *Processor {
	return &Processor{
		policy:     pol,
		inputPath:  inputPath,
		outputPath: outputPath,
	}
}

// Process applies all transformations specified in the policy to the PDF.
// Returns a receipt documenting the operations performed.
//
// Processing pipeline stages:
//  1. Input validation - verify PDF is valid and readable
//  2. Input hashing - compute input file hash for receipt
//  3. Input Copy - prepare working file
//  4. Visible labels - add watermark/footer/header (if enabled)
//  5. Provenance - embed document_id and copy_id (if enabled)
//  6. Tamper detection - embed content hash (if enabled)
//  7. Encryption - apply password and permissions (if enabled)
//  8. Output hashing - compute final file hash for receipt
func (p *Processor) Process() (*receipt.Receipt, error) {
	// Create success receipt initially
	rec := receipt.NewSuccess(consts.EngineVersion, p.policy.PolicyVersion)

	// Stage 1: Input validation
	if err := p.validateInput(rec); err != nil {
		return receipt.NewError(consts.EngineVersion, p.policy.PolicyVersion, receipt.ErrInputPDFInvalid, err.Error()), err
	}

	// Stage 2: Input hashing
	if err := p.computeInputHash(rec); err != nil {
		return receipt.NewError(consts.EngineVersion, p.policy.PolicyVersion, receipt.ErrInputReadFailed, err.Error()), err
	}

	// Prepare working file (intermediate)
	// We work on a temporary copy to avoid modifying input and to handle encryption last
	// We use .tmp suffix on the output path to ensure it's on the same filesystem
	workingPath := p.outputPath + ".tmp"
	if err := p.copyFile(p.inputPath, workingPath); err != nil {
		return receipt.NewError(consts.EngineVersion, p.policy.PolicyVersion, receipt.ErrInternalError, fmt.Sprintf("failed to create working file: %v", err)), err
	}
	defer os.Remove(workingPath) // Clean up temp file

	// Stage 3: Visible labels (if enabled)
	if p.policy.Labels != nil && p.policy.Labels.Mode == "visible" && p.policy.Labels.Visible != nil {
		if err := p.applyVisibleLabels(rec, workingPath); err != nil {
			return receipt.NewError(consts.EngineVersion, p.policy.PolicyVersion, receipt.ErrLabelFailed, err.Error()), err
		}
	}

	// Stage 4: Provenance (if enabled)
	if p.policy.Provenance != nil && p.policy.Provenance.Enabled {
		if err := p.applyProvenance(rec, workingPath); err != nil {
			return receipt.NewError(consts.EngineVersion, p.policy.PolicyVersion, receipt.ErrProvenanceFailed, err.Error()), err
		}
	}

	// Stage 5: Tamper detection (if enabled)
	if p.policy.TamperDetection != nil && p.policy.TamperDetection.Enabled {
		if err := p.applyTamperDetection(rec, workingPath); err != nil {
			return receipt.NewError(consts.EngineVersion, p.policy.PolicyVersion, receipt.ErrTamperHashFailed, err.Error()), err
		}
	}

	// Stage 6: Encryption (or Final Copy)
	if p.policy.Encryption.Enabled {
		// Encrypt working file to output file
		if err := p.applyEncryption(rec, workingPath); err != nil {
			return receipt.NewError(consts.EngineVersion, p.policy.PolicyVersion, receipt.ErrEncryptionFailed, err.Error()), err
		}
	} else {
		// If encryption is disabled, just move/copy working file to output
		if err := p.copyFile(workingPath, p.outputPath); err != nil {
			return receipt.NewError(consts.EngineVersion, p.policy.PolicyVersion, receipt.ErrOutputWriteFailed, err.Error()), err
		}
	}

	// Stage 7: Output hashing
	if err := p.computeOutputHash(rec); err != nil {
		return receipt.NewError(consts.EngineVersion, p.policy.PolicyVersion, receipt.ErrOutputWriteFailed, err.Error()), err
	}

	return rec, nil
}

// validateInput validates that the input PDF exists and is readable.
func (p *Processor) validateInput(rec *receipt.Receipt) error {
	info, err := os.Stat(p.inputPath)
	if os.IsNotExist(err) {
		return fmt.Errorf("input file does not exist: %s", p.inputPath)
	}
	if err != nil {
		return fmt.Errorf("failed to access input file: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("input path is a directory: %s", p.inputPath)
	}

	// Basic PDF magic bytes check
	f, err := os.Open(p.inputPath)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer f.Close()

	header := make([]byte, 5)
	if _, err := f.Read(header); err != nil {
		return fmt.Errorf("failed to read file header: %w", err)
	}

	if string(header) != "%PDF-" {
		return fmt.Errorf("file is not a valid PDF (invalid header)")
	}

	return nil
}

// applyEncryption encrypts the PDF according to the policy.
// inputPath here is the source file to encrypt (which is our working file)
func (p *Processor) applyEncryption(rec *receipt.Receipt, inputPath string) error {
	encResult, err := Encrypt(inputPath, p.outputPath, p.policy.Encryption)
	if err != nil {
		return err
	}

	// Add warnings from encryption to the receipt
	for _, w := range encResult.Warnings {
		rec.AddWarning(w.Code, w.Message)
	}

	return nil
}

// applyVisibleLabels adds visible watermark/footer/header to the PDF.
func (p *Processor) applyVisibleLabels(rec *receipt.Receipt, workingPath string) error {
	// Delegate to labels.go
	res, err := ApplyVisibleLabel(workingPath, p.policy.Labels.Visible)
	if err != nil {
		return err // Errors here should probably be fatal for the operation if we can't label
	}

	// Record warnings
	if len(res.Warnings) > 0 {
		rec.Warnings = append(rec.Warnings, res.Warnings...)
	}

	return nil
}

// applyProvenance embeds provenance information (document_id, copy_id) in the PDF.
func (p *Processor) applyProvenance(rec *receipt.Receipt, workingPath string) error {
	// Delegate to provenance.go
	res, err := ApplyProvenance(workingPath, p.policy.Provenance)
	if err != nil {
		return err
	}

	// Update receipt with generated IDs
	rec.DocumentID = res.DocumentID
	rec.CopyID = res.CopyID

	// Record warnings
	if len(res.Warnings) > 0 {
		rec.Warnings = append(rec.Warnings, res.Warnings...)
	}

	return nil
}

// applyTamperDetection embeds tamper detection information in the PDF.
func (p *Processor) applyTamperDetection(rec *receipt.Receipt, workingPath string) error {
	res, err := ApplyTamperDetection(workingPath, p.policy.TamperDetection)
	if err != nil {
		return err
	}

	if res.ContentHash != "" {
		rec.SetContentHash(res.ContentHash)
	}

	if len(res.Warnings) > 0 {
		rec.Warnings = append(rec.Warnings, res.Warnings...)
	}

	return nil
}

// computeInputHash computes the SHA-256 hash of the input file.
func (p *Processor) computeInputHash(rec *receipt.Receipt) error {
	res, err := HashFile(p.inputPath)
	if err != nil {
		return fmt.Errorf("failed to compute input hash: %w", err)
	}
	rec.InputSHA256 = res.SHA256
	return nil
}

// computeOutputHash computes the SHA-256 hash of the output file.
func (p *Processor) computeOutputHash(rec *receipt.Receipt) error {
	res, err := HashFile(p.outputPath)
	if err != nil {
		return fmt.Errorf("failed to compute output hash: %w", err)
	}
	rec.OutputSHA256 = res.SHA256
	return nil
}

// copyFile copies a file from src to dst.
func (p *Processor) copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return err
	}

	return destFile.Sync()
}
