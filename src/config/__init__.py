import json
import logging
from pathlib import Path
import jsonschema
from jsonschema.exceptions import ValidationError
from . import settings

logger = logging.getLogger(__name__)

SCHEMAS_PATH = Path(__file__).parent / "data_models.json"

def load_schemas() -> dict:
    """Loads and returns the JSON schemas defined in data_models.json."""
    with open(SCHEMAS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

# Load schemas once into memory
_SCHEMAS = load_schemas()

def validate_schema(data: dict, schema_name: str) -> bool:
    """
    Validates a dictionary against a named schema from data_models.json.
    Logs an error and returns False if validation fails.
    """
    if schema_name not in _SCHEMAS:
        logger.error("Schema '%s' not found in data_models.json", schema_name)
        return False
        
    schema = _SCHEMAS[schema_name]
    try:
        jsonschema.validate(instance=data, schema=schema)
        return True
    except ValidationError as e:
        logger.error("Schema validation failed for %s: %s", schema_name, e.message)
        logger.debug("Failing data: %s", data)
        return False

__all__ = ["settings", "load_schemas", "validate_schema"]