package consts

const (
	// EngineVersion is the current version of the securepdf-engine binary.
	// This is the single source of truth — all receipt builders and processors must use this.
	EngineVersion = "0.0.1"

	// Metadata keys for PDF Info dictionary
	MetadataDocumentID      = "SecurePDF_DocumentID"
	MetadataCopyID          = "SecurePDF_CopyID"
	MetadataVersion         = "SecurePDF_Version"
	MetadataTimestamp       = "SecurePDF_Timestamp"
	MetadataContentHash     = "SecurePDF_ContentHash"
	MetadataHashAlgorithm   = "SecurePDF_HashAlgorithm"
	MetadataTamperDetection = "SecurePDF_TamperDetection"
	MetadataHashProfile     = "SecurePDF_HashProfile"

	// Hash profiles
	HashProfileObjectsOnly    = "objects_only"    // Recommended V1 default
	HashProfileContentStreams = "content_streams" // V2 planned
	HashProfileExternal       = "external"        // Legacy/Basic

	// SecurePDFVersion is the metadata schema version embedded in PDF properties.
	// This is distinct from EngineVersion — it tracks the metadata format, not the binary.
	SecurePDFVersion = "1.0"
)
