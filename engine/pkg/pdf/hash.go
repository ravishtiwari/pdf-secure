package pdf

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
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

// HashPDFObjectsExcludingMetadata computes SHA-256 of all objects excluding Info dict.
// This ensures the hash remains stable even when metadata is updated (embedded hash).
func HashPDFObjectsExcludingMetadata(pdfPath string) (string, error) {
	// 1. Read PDF context
	// We pass nil for configuration to use defaults
	ctx, err := api.ReadContextFile(pdfPath)
	if err != nil {
		return "", fmt.Errorf("failed to read PDF context: %w", err)
	}

	// 2. Identify Info dictionary object number (to exclude)
	var infoObjNr int
	if ctx.XRefTable.Info != nil {
		infoObjNr = ctx.XRefTable.Info.ObjectNumber.Value()
	}

	// 3. Extract keys and SORT them (CRITICAL for determinism)
	keys := make([]int, 0, len(ctx.XRefTable.Table))
	for k := range ctx.XRefTable.Table {
		keys = append(keys, k)
	}
	sort.Ints(keys)

	// 4. Initialize Hasher
	hasher := sha256.New()

	// 5. Iterate over sorted keys
	for _, objNr := range keys {
		// Skip Info dict
		if objNr == infoObjNr {
			continue
		}

		// Retrieve object
		entry := ctx.XRefTable.Table[objNr]
		if entry.Free {
			continue
		}

		// Check for Metadata object (XMP) and exclude it
		if d, ok := entry.Object.(types.Dict); ok {
			if d["Type"] == types.Name("Metadata") {
				continue
			}
		}
		if sd, ok := entry.Object.(types.StreamDict); ok {
			if sd.Dict["Type"] == types.Name("Metadata") {
				continue
			}
		}

		// Hash the object (using stable serialization)
		// We include the object number to detect swapping
		if _, err := io.WriteString(hasher, fmt.Sprintf("%d:", objNr)); err != nil {
			return "", err
		}

		if err := hashObject(hasher, entry.Object); err != nil {
			return "", fmt.Errorf("failed to hash object %d: %w", objNr, err)
		}

		if _, err := io.WriteString(hasher, "\n"); err != nil {
			return "", err
		}
	}

	// 6. Return hex string
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// HashPDFContentStreams computes SHA-256 of content streams only, excluding metadata.
// This profile hashes only the actual content stream data (decoded bytes),
// making it sensitive to content changes but not to metadata/structure changes.
func HashPDFContentStreams(pdfPath string) (string, error) {
	ctx, err := api.ReadContextFile(pdfPath)
	if err != nil {
		return "", fmt.Errorf("failed to read PDF context: %w", err)
	}

	// Identify Info dictionary object number (to exclude)
	var infoObjNr int
	if ctx.XRefTable.Info != nil {
		infoObjNr = ctx.XRefTable.Info.ObjectNumber.Value()
	}

	// Extract and sort keys for determinism
	keys := make([]int, 0, len(ctx.XRefTable.Table))
	for k := range ctx.XRefTable.Table {
		keys = append(keys, k)
	}
	sort.Ints(keys)

	hasher := sha256.New()
	streamCount := 0

	for _, objNr := range keys {
		// Skip Info dict
		if objNr == infoObjNr {
			continue
		}

		entry := ctx.XRefTable.Table[objNr]
		if entry.Free {
			continue
		}

		// Only process StreamDict objects
		sd, ok := entry.Object.(types.StreamDict)
		if !ok {
			continue
		}

		// Skip Metadata streams
		if sd.Dict["Type"] == types.Name("Metadata") {
			continue
		}

		// Include object number for ordering stability
		if _, err := io.WriteString(hasher, fmt.Sprintf("stream:%d:", objNr)); err != nil {
			return "", err
		}

		// Hash the content stream data
		if sd.Content != nil {
			if _, err := hasher.Write(sd.Content); err != nil {
				return "", err
			}
		} else if sd.Raw != nil {
			if _, err := hasher.Write(sd.Raw); err != nil {
				return "", err
			}
		}

		if _, err := io.WriteString(hasher, "\n"); err != nil {
			return "", err
		}
		streamCount++
	}

	// If no streams found, fall back to whole-file hash for safety
	if streamCount == 0 {
		return HashPDFContent(pdfPath)
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// errWriter wraps an io.Writer and captures the first write error.
// After a write error, all subsequent writes become no-ops.
// This avoids the need to check every io.WriteString call individually.
type errWriter struct {
	w   io.Writer
	err error
}

func (ew *errWriter) Write(p []byte) (int, error) {
	if ew.err != nil {
		return 0, ew.err
	}
	n, err := ew.w.Write(p)
	if err != nil {
		ew.err = err
	}
	return n, err
}

// hashObject writes a deterministic string representation of the PDF object to the writer.
func hashObject(w io.Writer, obj types.Object) error {
	ew := &errWriter{w: w}
	hashObjectInner(ew, obj)
	return ew.err
}

// hashObjectInner recursively writes the PDF object representation.
// It uses errWriter so that once a write error occurs, all subsequent writes are no-ops.
func hashObjectInner(ew *errWriter, obj types.Object) {
	if ew.err != nil {
		return
	}

	switch t := obj.(type) {
	case types.Dict:
		io.WriteString(ew, "<<")
		// Sort keys
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, string(k))
		}
		sort.Strings(keys)

		for _, k := range keys {
			// Write key
			io.WriteString(ew, fmt.Sprintf("/%s ", k))
			// Write value
			hashObjectInner(ew, t[k])
			if ew.err != nil {
				return
			}
			io.WriteString(ew, " ") // Space separator
		}
		io.WriteString(ew, ">>")

	case types.Array:
		io.WriteString(ew, "[")
		for _, v := range t {
			hashObjectInner(ew, v)
			if ew.err != nil {
				return
			}
			io.WriteString(ew, " ")
		}
		io.WriteString(ew, "]")

	case types.StreamDict:
		// Hash Dict part
		hashObjectInner(ew, t.Dict)
		if ew.err != nil {
			return
		}
		io.WriteString(ew, "stream")
		// Hash Content
		if t.Content != nil {
			ew.Write(t.Content)
		} else if t.Raw != nil {
			ew.Write(t.Raw)
		}
		io.WriteString(ew, "endstream")

	case types.Name:
		io.WriteString(ew, fmt.Sprintf("/%s", string(t)))

	case types.StringLiteral:
		io.WriteString(ew, fmt.Sprintf("(%s)", string(t)))

	case types.HexLiteral:
		io.WriteString(ew, fmt.Sprintf("<%s>", string(t)))

	case types.IndirectRef:
		io.WriteString(ew, fmt.Sprintf("%d %d R", t.ObjectNumber, t.GenerationNumber))

	case types.Integer:
		io.WriteString(ew, fmt.Sprintf("%d", t))

	case types.Float:
		io.WriteString(ew, fmt.Sprintf("%f", float64(t)))

	case types.Boolean:
		io.WriteString(ew, fmt.Sprintf("%v", bool(t)))

	default:
		// Fallback for other types
		io.WriteString(ew, fmt.Sprintf("%v", t))
	}
}
