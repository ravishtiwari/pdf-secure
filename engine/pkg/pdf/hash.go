package pdf

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// HashResult holds file hash information.
type HashResult struct {
	SHA256 string
	Error  error
}

// HashFile computes SHA-256 hash of a file.
func HashFile(filePath string) (*HashResult, error) {
	result := &HashResult{}

	file, err := os.Open(filePath)
	if err != nil {
		result.Error = fmt.Errorf("failed to open file for hashing: %w", err)
		return result, result.Error
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		result.Error = fmt.Errorf("failed to hash file: %w", err)
		return result, result.Error
	}

	result.SHA256 = hex.EncodeToString(hasher.Sum(nil))
	return result, nil
}

// HashPDFContent computes hash of PDF content stream (for tamper detection).
// V1 implementation hashes the entire file bytes.
func HashPDFContent(pdfPath string) (string, error) {
	result, err := HashFile(pdfPath)
	if err != nil {
		return "", err
	}
	return result.SHA256, nil
}
