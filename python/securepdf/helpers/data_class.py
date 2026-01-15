import json
from dataclasses import dataclass, asdict
from typing import List, Optional


@dataclass
class Policy:
    password: str
    visible_label: Optional[str] = None
    invisible_label: bool = False
    provenance: bool = True
    encryption: str = "AES-256"
    key_derivation: str = "PBKDF2"

    def to_json(self) -> str:
        return json.dumps(asdict(self))


@dataclass
class Receipt:
    id: str
    timestamp: str
    status: str
    engine_version: str
    errors: List[str]
    warnings: List[str]
    policy_version: Optional[str] = None
    document_id: Optional[str] = None
    copy_id: Optional[str] = None
    input_hash: Optional[str] = None
    output_hash: Optional[str] = None
