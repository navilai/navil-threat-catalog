#!/usr/bin/env python3
"""
Navil Threat Catalog Validation Script

Validates the threats.json catalog for:
- Schema correctness (required fields)
- ID format consistency (AC-XX, AC-XX-XX, AC-XX-XX-XXX)
- Valid severity values
- Valid OWASP references
- No duplicate IDs
"""

import json
import sys
import re
from typing import List, Dict, Any

class ValidationError:
    def __init__(self, level: str, message: str):
        self.level = level  # "error", "warning"
        self.message = message

    def __str__(self):
        return f"[{self.level.upper()}] {self.message}"

class CatalogValidator:
    VALID_SEVERITIES = {"critical", "high", "medium", "low"}
    VALID_OWASP_REFS = {f"ASI{i:02d}" for i in range(1, 11)}

    ID_PATTERNS = {
        "attack_class": re.compile(r"^AC-\d{2}$"),
        "category": re.compile(r"^AC-\d{2}-\d{2}$"),
        "vector": re.compile(r"^AC-\d{2}-\d{2}-\d{3}$"),
    }

    def __init__(self):
        self.errors: List[ValidationError] = []
        self.seen_ids: Dict[str, str] = {}  # id -> context
        self.stats = {
            "attack_classes": 0,
            "categories": 0,
            "vectors": 0,
        }

    def load_catalog(self, path: str) -> bool:
        try:
            with open(path) as f:
                self.catalog = json.load(f)
            return True
        except json.JSONDecodeError as e:
            self.errors.append(ValidationError("error", f"Invalid JSON: {e}"))
            return False
        except FileNotFoundError:
            self.errors.append(ValidationError("error", f"File not found: {path}"))
            return False

    def validate(self) -> bool:
        if not hasattr(self, 'catalog'):
            self.errors.append(ValidationError("error", "Catalog not loaded"))
            return False

        # Validate top-level structure
        self._validate_root()

        # Validate each attack class
        for ac in self.catalog.get("attack_classes", []):
            self._validate_attack_class(ac)

        # Validate stats match actual counts
        self._validate_stats()

        return len([e for e in self.errors if e.level == "error"]) == 0

    def _validate_root(self):
        required = {"version", "license", "published", "stats", "attack_classes"}
        for field in required:
            if field not in self.catalog:
                self.errors.append(
                    ValidationError("error", f"Missing required field: {field}")
                )

        if self.catalog.get("license") != "CC-BY-SA-4.0":
            self.errors.append(
                ValidationError("warning", f"Unexpected license: {self.catalog.get('license')}")
            )

    def _validate_attack_class(self, ac: Dict[str, Any]):
        ac_id = ac.get("id")

        # Validate ID format
        if not ac_id:
            self.errors.append(ValidationError("error", "Attack class missing 'id'"))
            return

        if not self.ID_PATTERNS["attack_class"].match(ac_id):
            self.errors.append(
                ValidationError("error", f"Invalid attack class ID format: {ac_id}")
            )

        self._check_duplicate_id(ac_id, f"Attack class {ac_id}")
        self.stats["attack_classes"] += 1

        # Validate required fields
        for field in ["name", "description", "categories"]:
            if field not in ac:
                self.errors.append(
                    ValidationError("error", f"Attack class {ac_id} missing '{field}'")
                )

        # Validate OWASP refs
        self._validate_owasp_refs(ac.get("owasp_refs", []), ac_id)

        # Validate categories
        for category in ac.get("categories", []):
            self._validate_category(category, ac_id)

    def _validate_category(self, cat: Dict[str, Any], parent_ac_id: str):
        cat_id = cat.get("id")

        if not cat_id:
            self.errors.append(
                ValidationError("error", f"Category in {parent_ac_id} missing 'id'")
            )
            return

        if not self.ID_PATTERNS["category"].match(cat_id):
            self.errors.append(
                ValidationError("error", f"Invalid category ID format: {cat_id}")
            )

        # Verify category ID matches parent AC
        parent_from_id = cat_id[:5]  # AC-XX
        if parent_from_id != parent_ac_id:
            self.errors.append(
                ValidationError(
                    "error",
                    f"Category ID {cat_id} doesn't match parent {parent_ac_id}"
                )
            )

        self._check_duplicate_id(cat_id, f"Category {cat_id}")
        self.stats["categories"] += 1

        # Validate required fields
        for field in ["name", "description", "vectors"]:
            if field not in cat:
                self.errors.append(
                    ValidationError("error", f"Category {cat_id} missing '{field}'")
                )

        # Validate vectors
        for vector in cat.get("vectors", []):
            self._validate_vector(vector, cat_id)

    def _validate_vector(self, vec: Dict[str, Any], parent_cat_id: str):
        vec_id = vec.get("id")

        if not vec_id:
            self.errors.append(
                ValidationError("error", f"Vector in {parent_cat_id} missing 'id'")
            )
            return

        if not self.ID_PATTERNS["vector"].match(vec_id):
            self.errors.append(
                ValidationError("error", f"Invalid vector ID format: {vec_id}")
            )

        # Verify vector ID matches parent category
        parent_from_id = vec_id[:8]  # AC-XX-XX
        if parent_from_id != parent_cat_id:
            self.errors.append(
                ValidationError(
                    "error",
                    f"Vector ID {vec_id} doesn't match parent {parent_cat_id}"
                )
            )

        self._check_duplicate_id(vec_id, f"Vector {vec_id}")
        self.stats["vectors"] += 1

        # Validate required fields
        for field in ["name", "description", "severity", "owasp_refs", "example", "detection_hint"]:
            if field not in vec:
                self.errors.append(
                    ValidationError("error", f"Vector {vec_id} missing '{field}'")
                )

        # Validate severity
        severity = vec.get("severity")
        if severity not in self.VALID_SEVERITIES:
            self.errors.append(
                ValidationError(
                    "error",
                    f"Vector {vec_id} has invalid severity: {severity}"
                )
            )

        # Validate OWASP refs
        self._validate_owasp_refs(vec.get("owasp_refs", []), vec_id)

        # Validate detection_hint is not empty
        if not vec.get("detection_hint") or len(vec.get("detection_hint", "").strip()) < 10:
            self.errors.append(
                ValidationError(
                    "warning",
                    f"Vector {vec_id} detection_hint is too vague or empty"
                )
            )

    def _validate_owasp_refs(self, refs: List[str], context_id: str):
        for ref in refs:
            if ref not in self.VALID_OWASP_REFS:
                self.errors.append(
                    ValidationError(
                        "error",
                        f"{context_id} has invalid OWASP ref: {ref}"
                    )
                )

    def _check_duplicate_id(self, id_str: str, context: str):
        if id_str in self.seen_ids:
            self.errors.append(
                ValidationError(
                    "error",
                    f"Duplicate ID: {id_str} (seen in {self.seen_ids[id_str]})"
                )
            )
        self.seen_ids[id_str] = context

    def _validate_stats(self):
        expected_stats = self.catalog.get("stats", {})

        checks = [
            ("attack_classes", self.stats["attack_classes"]),
            ("detection_categories", self.stats["categories"]),
            ("base_vectors", self.stats["vectors"]),
        ]

        for stat_key, actual_count in checks:
            expected = expected_stats.get(stat_key)
            if expected != actual_count:
                self.errors.append(
                    ValidationError(
                        "error",
                        f"Stats mismatch: {stat_key} = {actual_count}, expected {expected}"
                    )
                )

    def print_report(self):
        error_count = len([e for e in self.errors if e.level == "error"])
        warning_count = len([e for e in self.errors if e.level == "warning"])

        print("\n" + "="*60)
        print("NAVIL THREAT CATALOG VALIDATION REPORT")
        print("="*60)

        print(f"\nStatistics:")
        print(f"  ✓ {self.stats['attack_classes']} attack classes")
        print(f"  ✓ {self.stats['categories']} detection categories")
        print(f"  ✓ {self.stats['vectors']} threat vectors")

        print(f"\nValidation Results:")
        print(f"  Errors: {error_count}")
        print(f"  Warnings: {warning_count}")

        if self.errors:
            print(f"\nDetails:")
            for error in self.errors:
                print(f"  {error}")

        print("\n" + "="*60)

        if error_count == 0:
            print("✓ VALIDATION PASSED")
            return 0
        else:
            print("✗ VALIDATION FAILED")
            return 1

def main():
    validator = CatalogValidator()

    if not validator.load_catalog("catalog/threats.json"):
        validator.print_report()
        return 1

    validator.validate()
    exit_code = validator.print_report()

    return exit_code

if __name__ == "__main__":
    sys.exit(main())
