package pdf

import (
	"fmt"
	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"securepdf-engine/pkg/policy"
	"securepdf-engine/pkg/receipt"
)

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
	conf, warnings := buildEncryptionConfig(encConfig)
	result.Warnings = append(result.Warnings, warnings...)

	// Encrypt PDF using pdfcpu
	err := api.EncryptFile(inputPath, outputPath, conf)
	if err != nil {
		result.Error = &receipt.Error{
			Code:    receipt.ErrEncryptionFailed,
			Message: fmt.Sprintf("PDF encryption failed: %v", err),
			Details: map[string]string{"crypto_profile": encConfig.CryptoProfile},
		}
		return result, err
	}

	result.Success = true
	return result, nil
}

// buildEncryptionConfig maps policy encryption config to pdfcpu config
func buildEncryptionConfig(encConfig policy.EncryptionConfig) (*model.Configuration, []receipt.Warning) {
	conf := model.NewDefaultConfiguration()
	warnings := []receipt.Warning{}

	// Set user password
	conf.UserPW = encConfig.UserPassword
	conf.OwnerPW = encConfig.UserPassword // V1: same as user password

	// Map crypto profile to encryption algorithm
	switch encConfig.CryptoProfile {
	case "strong":
		conf.EncryptUsingAES = true
		conf.EncryptKeyLength = 256
	case "compat":
		conf.EncryptUsingAES = true
		conf.EncryptKeyLength = 128
	case "legacy":
		conf.EncryptUsingAES = false
		conf.EncryptKeyLength = 128
		warnings = append(warnings, receipt.Warning{
			Code:    receipt.WarnWeakCryptoRequested,
			Message: "Using RC4-128 (legacy). Consider 'strong' or 'compat' for better security.",
		})
	default:
		// Default to strong
		conf.EncryptUsingAES = true
		conf.EncryptKeyLength = 256
	}

	// Map permissions
	conf.Permissions = buildPermissions(encConfig)

	return conf, warnings
}

// buildPermissions maps policy encryption config to pdfcpu permissions
func buildPermissions(encConfig policy.EncryptionConfig) model.PermissionFlags {
	perms := model.PermissionsNone

	if encConfig.AllowPrint {
		perms += model.PermissionPrintRev2 + model.PermissionPrintRev3
	}
	if encConfig.AllowCopy {
		perms += model.PermissionExtract + model.PermissionExtractRev3
	}
	if encConfig.AllowModify {
		perms += model.PermissionModify + model.PermissionModAnnFillForm + model.PermissionAssembleRev3
	}

	return perms
}
