package pdf

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"securepdf-engine/pkg/policy"
	"securepdf-engine/pkg/receipt"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
)

// alphanumericChars is the character set for random owner password generation.
const alphanumericChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// generateRandomPassword generates a cryptographically random alphanumeric password of the given length.
func generateRandomPassword(length int) (string, error) {
	b := make([]byte, length)
	for i := range b {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphanumericChars))))
		if err != nil {
			return "", fmt.Errorf("failed to generate random password: %w", err)
		}
		b[i] = alphanumericChars[idx.Int64()]
	}
	return string(b), nil
}

// EncryptionResult holds encryption operation results
type EncryptionResult struct {
	Success  bool
	Warnings []receipt.Warning
	Error    *receipt.Error
}

// Encrypt applies password-based encryption to a PDF
func Encrypt(inputPath, outputPath string, encConfig policy.EncryptionConfig) (*EncryptionResult, error) {
	result := &EncryptionResult{
		Success:  false,
		Warnings: []receipt.Warning{},
	}

	// Skip if encryption disabled
	if !encConfig.Enabled {
		result.Success = true
		return result, nil
	}

	// Map crypto profile to pdfcpu encryption config
	conf, warnings, err := buildEncryptionConfig(encConfig)
	if err != nil {
		result.Error = &receipt.Error{
			Code:    receipt.ErrEncryptionFailed,
			Message: fmt.Sprintf("Failed to build encryption config: %v", err),
		}
		return result, err
	}
	result.Warnings = append(result.Warnings, warnings...)

	// Encrypt PDF using pdfcpu
	err = api.EncryptFile(inputPath, outputPath, conf)
	if err != nil {
		// report effective profile in details
		profile := encConfig.CryptoProfile
		if profile == "" || profile == CryptoProfileAuto {
			profile = fmt.Sprintf("%s (default)", CryptoProfileStrong)
		}

		result.Error = &receipt.Error{
			Code:    receipt.ErrEncryptionFailed,
			Message: fmt.Sprintf("PDF encryption failed: %v", err),
			Details: map[string]string{"crypto_profile": profile},
		}
		return result, err
	}

	result.Success = true
	return result, nil
}

// EncryptionConfig Constants
const (
	CryptoProfileStrong = "strong"
	CryptoProfileCompat = "compat"
	CryptoProfileLegacy = "legacy"
	CryptoProfileAuto   = "auto"
)

// buildEncryptionConfig maps policy encryption config to pdfcpu config
func buildEncryptionConfig(encConfig policy.EncryptionConfig) (*model.Configuration, []receipt.Warning, error) {
	conf := model.NewDefaultConfiguration()
	warnings := []receipt.Warning{}

	// Set user password
	conf.UserPW = encConfig.UserPassword

	// Set owner password: use provided value, or generate a random 8-char alphanumeric password
	if encConfig.OwnerPassword != "" {
		conf.OwnerPW = encConfig.OwnerPassword
	} else {
		randomPW, err := generateRandomPassword(8)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate owner password: %w", err)
		}
		conf.OwnerPW = randomPW
	}

	// Determine effective profile (handle auto/empty)
	profile := encConfig.CryptoProfile
	if profile == "" || profile == CryptoProfileAuto {
		profile = CryptoProfileStrong
	}

	// Map crypto profile to encryption algorithm
	switch profile {
	case CryptoProfileStrong:
		conf.EncryptUsingAES = true
		conf.EncryptKeyLength = 256
	case CryptoProfileCompat:
		conf.EncryptUsingAES = true
		conf.EncryptKeyLength = 128
	case CryptoProfileLegacy:
		conf.EncryptUsingAES = false
		conf.EncryptKeyLength = 128
		warnings = append(warnings, receipt.Warning{
			Code:    receipt.WarnWeakCryptoRequested,
			Message: "Using RC4-128 (legacy). Consider 'strong' or 'compat' for better security.",
		})
	default:
		// Default to strong if unknown (though validation should catch this)
		conf.EncryptUsingAES = true
		conf.EncryptKeyLength = 256
	}

	// Map permissions
	conf.Permissions = buildPermissions(encConfig)

	return conf, warnings, nil
}

// buildPermissions maps policy encryption config to pdfcpu permissions
func buildPermissions(encConfig policy.EncryptionConfig) model.PermissionFlags {
	perms := model.PermissionsNone

	if encConfig.AllowPrint {
		perms |= model.PermissionPrintRev2 | model.PermissionPrintRev3
	}
	if encConfig.AllowCopy {
		perms |= model.PermissionExtract | model.PermissionExtractRev3
	}
	if encConfig.AllowModify {
		perms |= model.PermissionModify | model.PermissionModAnnFillForm | model.PermissionAssembleRev3
	}

	return perms
}
