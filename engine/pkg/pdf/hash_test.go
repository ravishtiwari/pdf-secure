package pdf

import (
	"os"
	"path/filepath"
	"testing"
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
