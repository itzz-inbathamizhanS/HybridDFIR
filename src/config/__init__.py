import json
from pathlib import Path
from . import settings

SCHEMAS_PATH = Path(__file__).parent / "data_models.json"

def load_schemas() -> dict:
    """Loads and returns the JSON schemas defined in data_models.json."""
    with open(SCHEMAS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

__all__ = ["settings", "load_schemas"]