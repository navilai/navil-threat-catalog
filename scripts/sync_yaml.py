#!/usr/bin/env python3
"""Regenerate threats.yaml from threats.json to keep them in sync."""

import json
import yaml
import pathlib

CATALOG_DIR = pathlib.Path(__file__).parent.parent / "catalog"

data = json.loads((CATALOG_DIR / "threats.json").read_text())
(CATALOG_DIR / "threats.yaml").write_text(
    yaml.dump(data, allow_unicode=True, default_flow_style=False, sort_keys=False, width=120)
)
print(f"threats.yaml synced ({data['stats']['base_vectors']} vectors)")
