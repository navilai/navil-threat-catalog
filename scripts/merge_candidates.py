#!/usr/bin/env python3
"""
Merge approved candidate vectors from a markdown file into threats.json.

Usage:
    python3 scripts/merge_candidates.py path/to/threat-catalog-candidates-YYYY-MM-DD.md

The script scans the markdown for JSON code blocks that are preceded by a line
containing a checkmark (unicode or ascii). Blocks without a checkmark are skipped.

Approved vectors are inserted into the correct attack class and category based
on the `proposed_class` and `proposed_category` fields, assigned the next
sequential ID, and stripped of metadata fields before writing.
"""

import json
import re
import sys
from pathlib import Path

CATALOG_DIR = Path(__file__).parent.parent / "catalog"
THREATS_JSON = CATALOG_DIR / "threats.json"

# Fields to strip from candidate vectors before merging
STRIP_FIELDS = {"proposed_class", "proposed_category", "rationale", "source"}

# Patterns that indicate approval on the line before or same line as a JSON block
APPROVE_PATTERNS = re.compile(r"[✅✓]|APPROVE", re.IGNORECASE)


def parse_approved_vectors(md_path: str) -> list[dict]:
    """Parse a candidates markdown file and return approved vector JSON blocks."""
    text = Path(md_path).read_text(encoding="utf-8")

    # Split into lines for context-aware scanning
    lines = text.split("\n")
    approved = []

    # Find all ```json ... ``` blocks and check if the preceding context has a checkmark
    in_json_block = False
    json_lines: list[str] = []
    block_start_line = 0
    preceding_context = ""

    for i, line in enumerate(lines):
        stripped = line.strip()

        if stripped.startswith("```json") and not in_json_block:
            in_json_block = True
            json_lines = []
            block_start_line = i
            # Gather preceding 3 lines as context for approval detection
            preceding_context = "\n".join(lines[max(0, i - 3) : i])
            continue

        if stripped == "```" and in_json_block:
            in_json_block = False
            json_text = "\n".join(json_lines)

            # Check if this block is approved
            if APPROVE_PATTERNS.search(preceding_context):
                try:
                    vec = json.loads(json_text)
                    # Only process vectors that look like candidates
                    if "proposed_class" in vec or "proposed_category" in vec:
                        approved.append(vec)
                except json.JSONDecodeError as e:
                    print(f"  WARNING: Invalid JSON at line {block_start_line + 1}: {e}")
            continue

        if in_json_block:
            json_lines.append(line)

    return approved


def next_vector_id(category: dict) -> str:
    """Compute the next sequential vector ID for a category."""
    cat_id = category["id"]
    vectors = category.get("vectors", [])
    if not vectors:
        return f"{cat_id}-001"

    # Extract numeric suffixes and find max
    max_num = 0
    for v in vectors:
        parts = v["id"].rsplit("-", 1)
        if len(parts) == 2:
            try:
                max_num = max(max_num, int(parts[1]))
            except ValueError:
                pass
    return f"{cat_id}-{max_num + 1:03d}"


def merge_vector(data: dict, vec: dict) -> str | None:
    """Insert a single vector into the catalog. Returns assigned ID or None on failure."""
    proposed_class = vec.get("proposed_class", "")
    proposed_category = vec.get("proposed_category", "")

    # Find the target category
    for ac in data["attack_classes"]:
        if ac["id"] != proposed_class:
            continue
        for cat in ac.get("categories", []):
            if cat["id"] != proposed_category:
                continue

            # Assign next sequential ID
            new_id = next_vector_id(cat)

            # Build clean vector (strip metadata fields)
            clean = {"id": new_id}
            for key in ["name", "description", "severity", "cve_refs", "owasp_refs",
                        "example", "detection_hint"]:
                if key in vec:
                    clean[key] = vec[key]

            # Ensure required fields have defaults
            clean.setdefault("cve_refs", [])
            clean.setdefault("owasp_refs", [])

            cat.setdefault("vectors", []).append(clean)
            return new_id

    print(f"  WARNING: Category {proposed_category} in class {proposed_class} not found")
    return None


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 scripts/merge_candidates.py <candidates.md>")
        print("  Parses the markdown for JSON blocks marked with a checkmark and merges them.")
        sys.exit(1)

    md_path = sys.argv[1]
    if not Path(md_path).exists():
        print(f"Error: File not found: {md_path}")
        sys.exit(1)

    # Parse approved vectors
    print(f"Reading candidates from: {md_path}")
    approved = parse_approved_vectors(md_path)

    if not approved:
        print("No approved vectors found. Mark vectors with a checkmark line before their JSON block.")
        print("Example:")
        print('  CANDIDATE-01 ✅')
        print('  ```json')
        print('  { ... }')
        print('  ```')
        sys.exit(0)

    print(f"Found {len(approved)} approved vectors")

    # Load catalog
    with open(THREATS_JSON) as f:
        data = json.load(f)

    old_count = data["stats"]["base_vectors"]
    print(f"Current catalog: {old_count} vectors")

    # Merge each approved vector
    merged = []
    for vec in approved:
        name = vec.get("name", "unnamed")
        new_id = merge_vector(data, vec)
        if new_id:
            merged.append((new_id, name, vec.get("severity", "unknown")))
            print(f"  + {new_id}: {name} ({vec.get('severity', '?')})")

    # Update stats
    total = sum(
        len(cat.get("vectors", []))
        for ac in data["attack_classes"]
        for cat in ac.get("categories", [])
    )
    data["stats"]["base_vectors"] = total

    # Write back
    with open(THREATS_JSON, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"\nMerged {len(merged)} vectors into threats.json ({old_count} -> {total})")


if __name__ == "__main__":
    main()
