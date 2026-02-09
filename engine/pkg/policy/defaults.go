package policy

func defaultEncryptionMode(enc EncryptionConfig) string {
	if enc.Enabled && enc.Mode == "" {
		return "password"
	}
	return enc.Mode
}

func defaultCryptoProfile(enc EncryptionConfig) string {
	if enc.CryptoProfile == "" {
		return "strong"
	}
	return enc.CryptoProfile
}

func defaultLabelsMode(labels *LabelsConfig) string {
	if labels == nil || labels.Mode == "" {
		return "off"
	}
	return labels.Mode
}

func defaultVisiblePlacement(visible *VisibleLabel) string {
	if visible != nil && visible.Placement == "" {
		return "footer"
	}
	return visible.Placement
}

func defaultVisiblePages(visible *VisibleLabel) string {
	if visible != nil && visible.Pages == "" {
		return "all"
	}
	return visible.Pages
}

func defaultInvisibleNamespace(invisible *InvisibleLabel) string {
	if invisible != nil && invisible.Namespace == "" {
		return "com.securepdf.v1"
	}
	return invisible.Namespace
}

func defaultProvenanceID(value string) string {
	if value == "" {
		return "auto"
	}
	return value
}

func defaultTamperHashAlg(tamper *TamperDetectionConfig) string {
	if tamper != nil && tamper.HashAlg == "" {
		return "sha256"
	}
	return tamper.HashAlg
}

func defaultTamperHashProfile(tamper *TamperDetectionConfig) string {
	if tamper != nil && tamper.HashProfile == "" {
		return "objects_only"
	}
	return tamper.HashProfile
}

func defaultAckText(ack *AckConfig) string {
	if ack != nil && ack.Text == "" {
		return "OSS_DEFAULT"
	}
	return ack.Text
}
