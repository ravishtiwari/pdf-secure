package pdf

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
	"securepdf-engine/pkg/policy"
)

func TestHashFile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "hash.txt")

	if err := os.WriteFile(path, []byte("hello"), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	result, err := HashFile(path)
	if err != nil {
		t.Fatalf("HashFile failed: %v", err)
	}

	expected := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if result.SHA256 != expected {
		t.Errorf("expected hash %s, got %s", expected, result.SHA256)
	}
}

func TestHashFileNotFound(t *testing.T) {
	_, err := HashFile("does-not-exist.pdf")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestHashPDFContent(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "content.pdf")

	if err := os.WriteFile(path, []byte("abc"), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	hashA, err := HashPDFContent(path)
	if err != nil {
		t.Fatalf("HashPDFContent failed: %v", err)
	}

	if err := os.WriteFile(path, []byte("abcd"), 0644); err != nil {
		t.Fatalf("failed to rewrite temp file: %v", err)
	}

	hashB, err := HashPDFContent(path)
	if err != nil {
		t.Fatalf("HashPDFContent failed: %v", err)
	}

	if hashA == hashB {
		t.Error("expected content hash to change after modification")
	}
}

func TestHashPDFContentStreamsChangesWithContent(t *testing.T) {
	tmpDir := t.TempDir()
	pdfPath := filepath.Join(tmpDir, "streams.pdf")
	createDummyPDF(t, pdfPath)
	normalizePDF(t, pdfPath)

	hashA, err := HashPDFContentStreams(pdfPath)
	if err != nil {
		t.Fatalf("HashPDFContentStreams failed: %v", err)
	}

	if _, err := ApplyVisibleLabel(pdfPath, &policy.VisibleLabel{
		Text:      "stream change",
		Placement: "footer",
		Pages:     "all",
	}); err != nil {
		t.Fatalf("ApplyVisibleLabel failed: %v", err)
	}

	hashB, err := HashPDFContentStreams(pdfPath)
	if err != nil {
		t.Fatalf("HashPDFContentStreams after mutation failed: %v", err)
	}

	if hashA == hashB {
		t.Fatal("expected content stream hash to change after PDF content changes")
	}
}

func TestHashObjectSerializesSupportedTypesDeterministically(t *testing.T) {
	obj := types.Dict{
		"Name":    types.Name("Example"),
		"String":  types.StringLiteral("hello"),
		"Hex":     types.HexLiteral("48656c6c6f"),
		"Array":   types.Array{types.Integer(7), types.Float(3.5), types.Boolean(true)},
		"Ref":     types.IndirectRef{ObjectNumber: types.Integer(10), GenerationNumber: types.Integer(0)},
		"Stream":  types.StreamDict{Dict: types.Dict{"Subtype": types.Name("XML")}, Content: []byte("payload")},
		"Default": nil,
	}

	var first bytes.Buffer
	if err := hashObject(&first, obj); err != nil {
		t.Fatalf("hashObject failed: %v", err)
	}

	var second bytes.Buffer
	if err := hashObject(&second, obj); err != nil {
		t.Fatalf("hashObject second pass failed: %v", err)
	}

	if first.String() != second.String() {
		t.Fatalf("expected deterministic serialization, got %q vs %q", first.String(), second.String())
	}
}

type failingWriter struct {
	failAfter int
	writes    int
}

func (fw *failingWriter) Write(p []byte) (int, error) {
	if fw.writes >= fw.failAfter {
		return 0, errors.New("forced write failure")
	}
	fw.writes++
	return len(p), nil
}

func TestHashObjectPropagatesWriterError(t *testing.T) {
	writer := &failingWriter{failAfter: 1}
	err := hashObject(writer, types.Dict{
		"One": types.StringLiteral("first"),
		"Two": types.StringLiteral("second"),
	})
	if err == nil {
		t.Fatal("expected hashObject to return writer error")
	}
}

func TestHashPDFObjectsExcludingMetadata(t *testing.T) {
	// 1. Create a dummy PDF
	tmpDir := t.TempDir()
	pdfPath := filepath.Join(tmpDir, "test.pdf")
	createDummyPDF(t, pdfPath)
	normalizePDF(t, pdfPath)

	// 2. Compute Objects-Only Hash
	hashA, err := HashPDFObjectsExcludingMetadata(pdfPath)
	if err != nil {
		t.Fatalf("Failed to compute hash A: %v", err)
	}

	// 3. Modify Metadata (add a key)
	// We use addMetadata from provenance.go (same package)
	meta := map[string]string{"TestKey": "TestValue"}
	if err := addMetadata(pdfPath, meta); err != nil {
		t.Fatalf("Failed to add metadata: %v", err)
	}

	// 4. Compute Hash again
	hashB, err := HashPDFObjectsExcludingMetadata(pdfPath)
	if err != nil {
		t.Fatalf("Failed to compute hash B: %v", err)
	}

	// 5. Assert Equality (Stability)
	if hashA != hashB {
		t.Errorf("Hash changed after metadata update!\nHash A: %s\nHash B: %s", hashA, hashB)
	}
}

func TestHashUnchangedAfterMetadataEmbed(t *testing.T) {
	// This test verifies that embedding the hash ITSELF doesn't change the object numbers
	// or the object content other than Info dict.

	tmpDir := t.TempDir()
	pdfPath := filepath.Join(tmpDir, "test_integrity.pdf")
	createDummyPDF(t, pdfPath)
	normalizePDF(t, pdfPath)

	// 1. Compute Hash
	hashA, err := HashPDFObjectsExcludingMetadata(pdfPath)
	if err != nil {
		t.Fatalf("Failed to compute hash A: %v", err)
	}

	// 2. Embed that hash into metadata
	meta := map[string]string{"SecurePDF_ContentHash": hashA}
	if err := addMetadata(pdfPath, meta); err != nil {
		t.Fatalf("Failed to embed metadata: %v", err)
	}

	// 3. Compute Hash of the file WITH the embedded hash
	hashB, err := HashPDFObjectsExcludingMetadata(pdfPath)
	if err != nil {
		t.Fatalf("Failed to compute hash B: %v", err)
	}

	// 4. Assert Equality
	if hashA != hashB {
		t.Errorf("Hash verification failed! Embedding the hash changed the file signature.\nHash A: %s\nHash B: %s", hashA, hashB)
	}
}

// Helper to create a minimal valid PDF
func createDummyPDF(t *testing.T, path string) {
	// Minimal PDF 1.7
	minimalPDF := []byte(`%PDF-1.7
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> /Contents 4 0 R >>
endobj
4 0 obj
<< /Length 12 >>
stream
Hello World
endstream
endobj
xref
0 5
0000000000 65535 f
0000000009 00000 n
0000000060 00000 n
0000000117 00000 n
0000000223 00000 n
trailer
<< /Size 5 /Root 1 0 R >>
startxref
285
%%EOF
`)
	if err := os.WriteFile(path, minimalPDF, 0644); err != nil {
		t.Fatalf("failed to create dummy pdf: %v", err)
	}
}

// Helper to normalize PDF using pdfcpu read/write cycle
func normalizePDF(t *testing.T, path string) {
	// We read and write the context to force pdfcpu to add any implicit objects (XMP, default resources)
	// This ensures that the state BEFORE hashing is consistent with the state AFTER adding metadata.
	// CRITICAL: We must use the SAME configuration as addMetadata (Disable Optimization)
	// otherwise the structure (ObjStm vs plain objects) will differ, causing hash mismatch.
	ctx, err := api.ReadContextFile(path)
	if err != nil {
		t.Fatalf("failed to read context for normalization: %v", err)
	}

	conf := model.NewDefaultConfiguration()
	conf.WriteObjectStream = false
	conf.WriteXRefStream = false

	// Set configuration on context
	ctx.Configuration = conf

	// Write back to same path
	if err := api.WriteContextFile(ctx, path); err != nil {
		t.Fatalf("failed to write normalized PDF: %v", err)
	}
}
