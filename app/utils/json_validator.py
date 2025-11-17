from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Optional

try:
    import jsonschema
    from jsonschema import ValidationError, validate
except ImportError:
    jsonschema = None
    ValidationError = Exception
    validate = None


SCAN_SCHEMA_PATH = Path(__file__).parent.parent.parent / "data" / "schemas" / "scan.schema.json"


def load_schema(schema_path: Optional[Path] = None) -> Dict:
    """Load JSON schema for scan validation."""
    path = schema_path or SCAN_SCHEMA_PATH
    if path.exists():
        return json.loads(path.read_text())
    # Fallback: minimal schema structure
    return {
        "type": "object",
        "properties": {
            "vulnerabilities": {"type": "object"},
            "systemStats": {"type": "object"},
        },
        "required": ["vulnerabilities", "systemStats"],
    }


def validate_scan_json(scan_data: Dict, schema_path: Optional[Path] = None) -> tuple[bool, Optional[str]]:
    """
    Validate scan JSON against schema.
    
    Returns:
        (is_valid, error_message)
    """
    if not jsonschema:
        # If jsonschema not installed, skip validation
        return True, None
    
    try:
        schema = load_schema(schema_path)
        validate(instance=scan_data, schema=schema)
        return True, None
    except ValidationError as e:
        return False, f"Validation error: {e.message} at path: {'.'.join(str(p) for p in e.path)}"
    except Exception as e:
        return False, f"Schema validation failed: {str(e)}"
