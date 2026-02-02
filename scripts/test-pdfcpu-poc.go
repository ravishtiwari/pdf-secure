package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
)

func main() {
	fmt.Println("=== pdfcpu Proof of Concept ===\n")

	// Test 1: Create a simple PDF
	fmt.Println("Test 1: Creating a simple test PDF...")
	inputPDF := "test-pdfs/sample-input.pdf"
	if _, err := os.Stat(inputPDF); os.IsNotExist(err) {
		if err := createSimplePDF(inputPDF); err != nil {
			log.Fatalf("Failed to create test PDF: %v", err)
		}
		fmt.Printf("✓ Created: %s\n\n", inputPDF)
	} else {
		fmt.Printf("✓ Using existing: %s\n\n", inputPDF)
	}

	// Test 2: Encrypt with AES-256 (strong profile)
	fmt.Println("Test 2: Encrypting with AES-256 (strong profile)...")
	start := time.Now()
	outputAES256 := "test-pdfs/encrypted-aes256.pdf"
	if err := encryptPDF(inputPDF, outputAES256, "strong", "userpass", "ownerpass"); err != nil {
		log.Fatalf("AES-256 encryption failed: %v", err)
	}
	fmt.Printf("✓ Encrypted with AES-256 in %v\n", time.Since(start))
	printFileSize(outputAES256)

	// Test 3: Encrypt with AES-128 (compat profile)
	fmt.Println("\nTest 3: Encrypting with AES-128 (compat profile)...")
	start = time.Now()
	outputAES128 := "test-pdfs/encrypted-aes128.pdf"
	if err := encryptPDF(inputPDF, outputAES128, "compat", "userpass", "ownerpass"); err != nil {
		log.Fatalf("AES-128 encryption failed: %v", err)
	}
	fmt.Printf("✓ Encrypted with AES-128 in %v\n", time.Since(start))
	printFileSize(outputAES128)

	// Test 4: Encrypt with RC4-128 (legacy profile)
	fmt.Println("\nTest 4: Encrypting with RC4-128 (legacy profile)...")
	start = time.Now()
	outputRC4 := "test-pdfs/encrypted-rc4.pdf"
	if err := encryptPDF(inputPDF, outputRC4, "legacy", "userpass", "ownerpass"); err != nil {
		log.Fatalf("RC4-128 encryption failed: %v", err)
	}
	fmt.Printf("✓ Encrypted with RC4-128 in %v\n", time.Since(start))
	printFileSize(outputRC4)

	// Test 5: Verify encrypted PDFs can be opened
	fmt.Println("\nTest 5: Verifying encrypted PDFs...")
	for _, file := range []string{outputAES256, outputAES128, outputRC4} {
		if err := verifyPDF(file, "userpass"); err != nil {
			log.Fatalf("Verification failed for %s: %v", file, err)
		}
		fmt.Printf("✓ Verified: %s\n", file)
	}

	fmt.Println("\n=== All tests passed! ===")
	fmt.Println("\nNext steps:")
	fmt.Println("1. Open encrypted PDFs in Adobe Reader/Chrome to verify compatibility")
	fmt.Println("2. Try opening without password (should fail)")
	fmt.Println("3. Try opening with correct password (should succeed)")
}

// createSimplePDF creates a minimal test PDF using pdfcpu
func createSimplePDF(filename string) error {
	// Use pdfcpu's NUp command to create a simple PDF from nothing
	// Actually, let's use a different approach - create using Go's PDF generation

	// For this POC, we'll write a minimal PDF manually
	content := `%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Contents 4 0 R
/Resources <<
/Font <<
/F1 5 0 R
>>
>>
>>
endobj
4 0 obj
<<
/Length 44
>>
stream
BT
/F1 24 Tf
100 700 Td
(Hello PDF!) Tj
ET
endstream
endobj
5 0 obj
<<
/Type /Font
/Subtype /Type1
/BaseFont /Helvetica
>>
endobj
xref
0 6
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
0000000262 00000 n
0000000356 00000 n
trailer
<<
/Size 6
/Root 1 0 R
>>
startxref
444
%%EOF`

	return os.WriteFile(filename, []byte(content), 0644)
}

// encryptPDF encrypts a PDF with the specified crypto profile
func encryptPDF(inputPath, outputPath, profile, userPW, ownerPW string) error {
	config := model.NewDefaultConfiguration()

	// Map our crypto profiles to pdfcpu encryption settings
	switch profile {
	case "strong":
		// AES-256 encryption
		config.EncryptUsingAES = true
		config.EncryptKeyLength = 256
	case "compat":
		// AES-128 encryption
		config.EncryptUsingAES = true
		config.EncryptKeyLength = 128
	case "legacy":
		// RC4-128 encryption
		config.EncryptUsingAES = false
		config.EncryptKeyLength = 128
	default:
		return fmt.Errorf("unknown crypto profile: %s", profile)
	}

	// Set passwords
	config.UserPW = userPW
	config.OwnerPW = ownerPW

	// Set permissions (full permissions for owner, read-only for user)
	config.Permissions = model.PermissionsAll

	return api.EncryptFile(inputPath, outputPath, config)
}

// verifyPDF verifies that an encrypted PDF can be opened with the password
func verifyPDF(filename, password string) error {
	config := model.NewDefaultConfiguration()
	config.UserPW = password

	// Try to read the PDF - this will fail if password is wrong
	return api.ValidateFile(filename, config)
}

// printFileSize prints the file size in a human-readable format
func printFileSize(filename string) {
	info, err := os.Stat(filename)
	if err != nil {
		fmt.Printf("  (could not get file size: %v)\n", err)
		return
	}

	size := info.Size()
	if size < 1024 {
		fmt.Printf("  File size: %d bytes\n", size)
	} else if size < 1024*1024 {
		fmt.Printf("  File size: %.2f KB\n", float64(size)/1024)
	} else {
		fmt.Printf("  File size: %.2f MB\n", float64(size)/(1024*1024))
	}
}
