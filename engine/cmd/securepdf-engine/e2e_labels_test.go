package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"securepdf-engine/pkg/consts"
	"securepdf-engine/pkg/policy"
	"securepdf-engine/pkg/receipt"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
)

func TestE2EVisibleLabelFooter(t *testing.T) {
	inputPath := "../../test-pdfs/sample-input.pdf"

	pol := &policy.Policy{
		PolicyVersion: "1.0",
		Encryption:    policy.EncryptionConfig{Enabled: false},
		Labels: &policy.LabelsConfig{
			Mode: "visible",
			Visible: &policy.VisibleLabel{
				Text:      "CONFIDENTIAL",
				Placement: "footer",
				Pages:     "all",
			},
		},
	}

	outputPath, rec := runSecureWithPolicy(t, inputPath, pol)

	if !rec.OK {
		t.Fatalf("expected receipt OK to be true, got error: %+v", rec.Error)
	}

	content := extractPageContent(t, outputPath, 1, "")
	if !contentContainsLabel(content, "CONFIDENTIAL") {
		t.Fatalf("expected footer label text in page content")
	}
}

func TestE2EVisibleLabelFirstPageOnly(t *testing.T) {
	inputPath := "../../test-pdfs/sample-input.pdf"
	multiPageInput := createMultiPagePDF(t, inputPath)

	pol := &policy.Policy{
		PolicyVersion: "1.0",
		Encryption:    policy.EncryptionConfig{Enabled: false},
		Labels: &policy.LabelsConfig{
			Mode: "visible",
			Visible: &policy.VisibleLabel{
				Text:      "FIRST PAGE",
				Placement: "footer",
				Pages:     "first",
			},
		},
	}

	outputPath, rec := runSecureWithPolicy(t, multiPageInput, pol)
	if !rec.OK {
		t.Fatalf("expected receipt OK to be true, got error: %+v", rec.Error)
	}

	page1 := extractPageContent(t, outputPath, 1, "")
	page2 := extractPageContent(t, outputPath, 2, "")

	if !contentContainsLabel(page1, "FIRST PAGE") {
		t.Fatalf("expected label text on page 1")
	}
	if contentContainsLabel(page2, "FIRST PAGE") {
		t.Fatalf("expected no label text on page 2")
	}
}

func TestE2EProvenanceIDs(t *testing.T) {
	inputPath := "../../test-pdfs/sample-input.pdf"

	pol := &policy.Policy{
		PolicyVersion: "1.0",
		Encryption:    policy.EncryptionConfig{Enabled: false},
		Provenance: &policy.ProvenanceConfig{
			Enabled:    true,
			DocumentID: "auto",
			CopyID:     "auto",
		},
	}

	outputPath, rec := runSecureWithPolicy(t, inputPath, pol)
	if !rec.OK {
		t.Fatalf("expected receipt OK to be true, got error: %+v", rec.Error)
	}

	docPattern := regexp.MustCompile(`^doc-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	copyPattern := regexp.MustCompile(`^copy-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

	if !docPattern.MatchString(rec.DocumentID) {
		t.Fatalf("document_id not in UUIDv4 format: %s", rec.DocumentID)
	}
	if !copyPattern.MatchString(rec.CopyID) {
		t.Fatalf("copy_id not in UUIDv4 format: %s", rec.CopyID)
	}

	props, err := readProperties(outputPath, "")
	if err != nil {
		t.Fatalf("failed to read properties: %v", err)
	}
	if props[consts.MetadataDocumentID] != rec.DocumentID {
		t.Fatalf("document_id not embedded in metadata")
	}
	if props[consts.MetadataCopyID] != rec.CopyID {
		t.Fatalf("copy_id not embedded in metadata")
	}
}

func TestE2EEncryptionWithLabelsAndProvenance(t *testing.T) {
	inputPath := "../../test-pdfs/sample-input.pdf"
	password := "LabelProvEncrypt123!"

	pol := &policy.Policy{
		PolicyVersion: "1.0",
		Encryption: policy.EncryptionConfig{
			Enabled:       true,
			Mode:          "password",
			UserPassword:  password,
			AllowPrint:    true,
			AllowCopy:     false,
			AllowModify:   false,
			CryptoProfile: "strong",
		},
		Labels: &policy.LabelsConfig{
			Mode: "visible",
			Visible: &policy.VisibleLabel{
				Text:      "CONFIDENTIAL",
				Placement: "footer",
				Pages:     "all",
			},
		},
		Provenance: &policy.ProvenanceConfig{
			Enabled:    true,
			DocumentID: "auto",
			CopyID:     "auto",
		},
	}

	outputPath, rec := runSecureWithPolicy(t, inputPath, pol)
	if !rec.OK {
		t.Fatalf("expected receipt OK to be true, got error: %+v", rec.Error)
	}

	if _, err := readProperties(outputPath, ""); err == nil {
		t.Fatalf("expected encrypted PDF to require a password for properties")
	}

	props, err := readProperties(outputPath, password)
	if err != nil {
		t.Fatalf("failed to read encrypted properties: %v", err)
	}
	if props[consts.MetadataDocumentID] != rec.DocumentID {
		t.Fatalf("document_id not embedded in encrypted metadata")
	}
	if props[consts.MetadataCopyID] != rec.CopyID {
		t.Fatalf("copy_id not embedded in encrypted metadata")
	}

	content := extractPageContent(t, outputPath, 1, password)
	if !contentContainsLabel(content, "CONFIDENTIAL") {
		t.Fatalf("expected label text in encrypted PDF content")
	}
}

func runSecureWithPolicy(t *testing.T, inputPath string, pol *policy.Policy) (string, *receipt.Receipt) {
	t.Helper()
	tmpDir := t.TempDir()
	policyPath := writePolicyFile(t, tmpDir, pol)
	outputPath := filepath.Join(tmpDir, "out.pdf")
	receiptPath := filepath.Join(tmpDir, "receipt.json")

	args := []string{
		"--in", inputPath,
		"--out", outputPath,
		"--policy", policyPath,
		"--receipt", receiptPath,
	}

	if err := runSecure(args); err != nil {
		t.Fatalf("runSecure failed: %v", err)
	}

	rec, err := receipt.Load(receiptPath)
	if err != nil {
		t.Fatalf("failed to load receipt: %v", err)
	}

	return outputPath, rec
}

func writePolicyFile(t *testing.T, dir string, pol *policy.Policy) string {
	t.Helper()
	data, err := json.MarshalIndent(pol, "", "  ")
	if err != nil {
		t.Fatalf("failed to serialize policy: %v", err)
	}
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("failed to write policy: %v", err)
	}
	return path
}

func createMultiPagePDF(t *testing.T, inputPath string) string {
	t.Helper()
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "multi-page.pdf")
	if err := api.MergeCreateFile([]string{inputPath, inputPath}, outPath, false, nil); err != nil {
		t.Fatalf("failed to create multi-page PDF: %v", err)
	}
	return outPath
}

func extractPageContent(t *testing.T, pdfPath string, page int, password string) string {
	t.Helper()
	f, err := os.Open(pdfPath)
	if err != nil {
		t.Fatalf("failed to open PDF: %v", err)
	}
	defer f.Close()

	conf := model.NewDefaultConfiguration()
	if password != "" {
		conf.UserPW = password
	}

	ctx, err := api.ReadContext(f, conf)
	if err != nil {
		t.Fatalf("failed to read PDF context: %v", err)
	}
	if err := api.ValidateContext(ctx); err != nil {
		t.Fatalf("failed to validate PDF context: %v", err)
	}

	var buffer bytes.Buffer
	if err := appendPageContent(ctx, &buffer, page); err != nil {
		t.Fatalf("failed to extract content: %v", err)
	}
	return buffer.String()
}

func appendPageContent(ctx *model.Context, buffer *bytes.Buffer, page int) error {
	r, err := pdfcpu.ExtractPageContent(ctx, page)
	if err != nil {
		return err
	}
	if r != nil {
		data, err := io.ReadAll(r)
		if err != nil {
			return err
		}
		buffer.Write(data)
	}

	pageDict, _, _, err := ctx.PageDict(page, false)
	if err != nil {
		return err
	}
	if pageDict == nil {
		return nil
	}

	resourcesObj, ok := pageDict.Find("Resources")
	if !ok || resourcesObj == nil {
		return nil
	}
	resources, err := ctx.DereferenceDict(resourcesObj)
	if err != nil {
		return err
	}

	xObjectObj, ok := resources.Find("XObject")
	if !ok || xObjectObj == nil {
		return nil
	}
	xObjectDict, err := ctx.DereferenceDict(xObjectObj)
	if err != nil {
		return err
	}

	for _, obj := range xObjectDict {
		ir, ok := obj.(types.IndirectRef)
		if !ok {
			continue
		}
		sd, _, err := ctx.DereferenceStreamDict(ir)
		if err != nil {
			return err
		}
		if sd == nil {
			continue
		}
		if err := sd.Decode(); err != nil {
			return err
		}
		buffer.Write(sd.Content)
	}

	return nil
}

func readProperties(pdfPath string, password string) (map[string]string, error) {
	f, err := os.Open(pdfPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	conf := model.NewDefaultConfiguration()
	if password != "" {
		conf.UserPW = password
	}

	return api.Properties(f, conf)
}

func contentContainsLabel(content string, label string) bool {
	if strings.Contains(content, label) {
		return true
	}

	// Some streams encode text as UTF-16 with NUL bytes.
	if strings.Contains(stripNulls(content), label) {
		return true
	}

	return false
}

func stripNulls(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != 0 {
			b = append(b, s[i])
		}
	}
	return string(b)
}
