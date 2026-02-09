"""Policy models for SecurePDF V1 schema."""

from enum import Enum
import json
from dataclasses import dataclass, asdict, field
from beartype import beartype
from typing import Optional


class LabelsConfig(str, Enum):
    PLACEMENT_HEADER: str = "header"
    PLACEMENT_FOOTER: str = "footer"


@beartype
@dataclass
class EncryptionConfig:
    """Encryption settings for the secured PDF."""

    enabled: bool = True
    mode: str = "password"  # "password" only in V1
    user_password: str = ""
    owner_password: str = (
        ""  # If empty, engine generates a random 8-char alphanumeric password
    )
    allow_print: bool = False
    allow_copy: bool = False
    allow_modify: bool = False
    crypto_profile: str = "strong"  # "strong"|"compat"|"legacy"

    @classmethod
    def from_dict(cls, data: dict) -> "EncryptionConfig":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@beartype
@dataclass
class AckConfig:
    """Custodianship acknowledgment settings."""

    required: bool = True
    text: str = "OSS_DEFAULT"  # "OSS_DEFAULT" in V1
    viewer_dependent: bool = True

    @classmethod
    def from_dict(cls, data: dict) -> "AckConfig":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@beartype
@dataclass
class VisibleLabel:
    """Settings for visible watermark/label overlays."""

    text: str = ""
    placement: str = "footer"  # "footer"|"header"
    pages: str = "all"  # "all"|"first"|"range"
    page_range: Optional[str] = None  # e.g., "1-3,8,10-12"

    @classmethod
    def from_dict(cls, data: dict) -> "VisibleLabel":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@beartype
@dataclass
class InvisibleLabel:
    """Settings for invisible metadata markers."""

    enabled: bool = True
    namespace: str = "com.securepdf.v1"

    @classmethod
    def from_dict(cls, data: dict) -> "InvisibleLabel":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@beartype
@dataclass
class LabelsConfig:
    """Visible and invisible label settings."""

    mode: str = "off"  # "visible"|"invisible"|"off"
    visible: Optional[VisibleLabel] = None
    invisible: Optional[InvisibleLabel] = None

    @classmethod
    def from_dict(cls, data: dict) -> "LabelsConfig":
        visible = data.get("visible")
        if visible and isinstance(visible, dict):
            visible = VisibleLabel.from_dict(visible)
        invisible = data.get("invisible")
        if invisible and isinstance(invisible, dict):
            invisible = InvisibleLabel.from_dict(invisible)
        return cls(
            mode=data.get("mode", "off"),
            visible=visible,
            invisible=invisible,
        )


@beartype
@dataclass
class ProvenanceConfig:
    """Document provenance tracking settings."""

    enabled: bool = True
    document_id: str = "auto"  # "auto" or custom string
    copy_id: str = "auto"  # "auto" or custom string

    @classmethod
    def from_dict(cls, data: dict) -> "ProvenanceConfig":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@beartype
@dataclass
class TamperDetectionConfig:
    """Tamper detection settings."""

    enabled: bool = True
    hash_alg: str = "sha256"  # "sha256" only in V1

    @classmethod
    def from_dict(cls, data: dict) -> "TamperDetectionConfig":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@beartype
@dataclass
class Policy:
    """Policy defining transformation and security rules for a PDF (V1 schema)."""

    policy_version: str = "1.0"
    encryption: EncryptionConfig = field(default_factory=EncryptionConfig)
    ack: Optional[AckConfig] = None
    labels: Optional[LabelsConfig] = None
    provenance: Optional[ProvenanceConfig] = None
    tamper_detection: Optional[TamperDetectionConfig] = None

    @classmethod
    def from_dict(cls, data: dict) -> "Policy":
        """Create a Policy from a dictionary."""
        encryption_data = data.get("encryption")
        encryption = (
            EncryptionConfig.from_dict(encryption_data)
            if encryption_data
            else EncryptionConfig()
        )

        ack_data = data.get("ack")
        ack = AckConfig.from_dict(ack_data) if ack_data else None

        labels_data = data.get("labels")
        labels = LabelsConfig.from_dict(labels_data) if labels_data else None

        provenance_data = data.get("provenance")
        provenance = (
            ProvenanceConfig.from_dict(provenance_data) if provenance_data else None
        )

        tamper_data = data.get("tamper_detection")
        tamper_detection = (
            TamperDetectionConfig.from_dict(tamper_data) if tamper_data else None
        )

        return cls(
            policy_version=data.get("policy_version", "1.0"),
            encryption=encryption,
            ack=ack,
            labels=labels,
            provenance=provenance,
            tamper_detection=tamper_detection,
        )

    def to_json(self) -> str:
        """Serialize policy to JSON string for engine consumption."""

        def dict_factory(items):
            """Custom dict factory to handle nested dataclasses and None values."""
            result = {}
            for key, value in items:
                if value is None:
                    continue  # Skip None values
                if hasattr(value, "__dataclass_fields__"):
                    result[key] = asdict(value, dict_factory=dict_factory)
                else:
                    result[key] = value
            return result

        return json.dumps(asdict(self, dict_factory=dict_factory), indent=2)
