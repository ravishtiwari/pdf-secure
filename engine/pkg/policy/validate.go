package policy

import (
	"fmt"

	"securepdf-engine/pkg/options"
	"securepdf-engine/pkg/receipt"
)

// ValidationResult captures the outcome of a policy validation.
type ValidationResult struct {
	Valid    bool
	Warnings []receipt.Warning
	Error    *receipt.Error
}

// Validate performs comprehensive validation against the V1 contract.
func (policy *Policy) Validate() *ValidationResult {
	result := &ValidationResult{
		Valid:    true,
		Warnings: []receipt.Warning{},
	}

	if err := policy.validateVersion(); err != nil {
		return fail(result, err)
	}
	if err := policy.validateEncryption(result); err != nil {
		return fail(result, err)
	}
	if err := policy.validateAck(); err != nil {
		return fail(result, err)
	}
	if err := policy.validateLabels(); err != nil {
		return fail(result, err)
	}
	if err := policy.validateProvenance(); err != nil {
		return fail(result, err)
	}
	if err := policy.validateTamperDetection(); err != nil {
		return fail(result, err)
	}

	return result
}

// ValidateWithOptions applies engine options (e.g., reject weak crypto) after base validation.
func (policy *Policy) ValidateWithOptions(opts *options.EngineOptions) *ValidationResult {
	res := policy.Validate()
	if !res.Valid {
		return res
	}
	if opts == nil {
		return res
	}

	if opts.RejectWeakCrypto {
		for _, warning := range res.Warnings {
			if warning.Code == receipt.WarnWeakCryptoRequested {
				res.Valid = false
				res.Error = &receipt.Error{
					Code:    receipt.ErrPolicyInvalid,
					Message: "weak crypto profile rejected by engine option reject_weak_crypto",
					Details: map[string]string{
						"option":         "reject_weak_crypto",
						"crypto_profile": policy.Encryption.CryptoProfile,
					},
				}
				break
			}
		}
	}

	return res
}

func (policy *Policy) validateVersion() *receipt.Error {
	if policy.PolicyVersion == "" {
		return validationError("policy_version", "policy_version is required")
	}
	if policy.PolicyVersion != "1.0" {
		return validationError("policy_version", fmt.Sprintf("unsupported policy_version %q (expected 1.0)", policy.PolicyVersion))
	}
	return nil
}

func (policy *Policy) validateEncryption(result *ValidationResult) *receipt.Error {
	enc := policy.Encryption

	if !enc.Enabled {
		return nil
	}

	mode := defaultEncryptionMode(enc)
	if mode != "password" {
		return validationError("encryption.mode", "encryption.mode must be 'password' in V1")
	}

	if enc.UserPassword == "" {
		return validationError("encryption.user_password", "encryption.user_password is required when encryption.enabled is true")
	}

	cryptoProfile := defaultCryptoProfile(enc)
	switch cryptoProfile {
	case "strong":
		// ok
	case "compat", "legacy":
		msg, _ := receipt.WarningMessage(receipt.WarnWeakCryptoRequested)
		result.Warnings = append(result.Warnings, receipt.Warning{
			Code:    receipt.WarnWeakCryptoRequested,
			Message: fmt.Sprintf("%s (profile=%s)", msg, cryptoProfile),
		})
	default:
		return validationError("encryption.crypto_profile", "crypto_profile must be one of strong|compat|legacy")
	}

	return nil
}

func (policy *Policy) validateAck() *receipt.Error {
	if policy.Ack == nil {
		return nil
	}
	text := defaultAckText(policy.Ack)
	if text != "OSS_DEFAULT" {
		return validationError("ack.text", "only OSS_DEFAULT is supported in V1")
	}
	return nil
}

func (policy *Policy) validateLabels() *receipt.Error {
	if policy.Labels == nil {
		return nil
	}

	mode := defaultLabelsMode(policy.Labels)

	switch mode {
	case "visible":
		if policy.Labels.Visible == nil {
			return validationError("labels.visible", "labels.visible configuration required when mode=visible")
		}
		vis := policy.Labels.Visible
		if vis.Text == "" {
			return validationError("labels.visible.text", "labels.visible.text is required when mode=visible")
		}
		placement := defaultVisiblePlacement(vis)
		switch placement {
		case "footer", "header":
		default:
			return validationError("labels.visible.placement", "placement must be footer|header")
		}
		pages := defaultVisiblePages(vis)
		switch pages {
		case "all", "first", "range":
		default:
			return validationError("labels.visible.pages", "pages must be all|first|range")
		}
		if pages == "range" && vis.PageRange == "" {
			return validationError("labels.visible.page_range", "page_range required when pages=range")
		}
	case "invisible":
		if policy.Labels.Invisible == nil {
			return validationError("labels.invisible", "labels.invisible configuration required when mode=invisible")
		}
	case "off":
		// ok
	default:
		return validationError("labels.mode", "labels.mode must be visible|invisible|off")
	}

	return nil
}

func (policy *Policy) validateProvenance() *receipt.Error {
	if policy.Provenance == nil || !policy.Provenance.Enabled {
		return nil
	}
	return nil
}

func (policy *Policy) validateTamperDetection() *receipt.Error {
	if policy.TamperDetection == nil || !policy.TamperDetection.Enabled {
		return nil
	}
	hashAlg := defaultTamperHashAlg(policy.TamperDetection)
	if hashAlg != "sha256" {
		return validationError("tamper_detection.hash_alg", "only sha256 is supported in V1")
	}
	return nil
}

func validationError(field, message string) *receipt.Error {
	return &receipt.Error{
		Code:    receipt.ErrPolicyInvalid,
		Message: message,
		Details: map[string]string{"field": field},
	}
}

func fail(result *ValidationResult, err *receipt.Error) *ValidationResult {
	result.Valid = false
	result.Error = err
	return result
}
