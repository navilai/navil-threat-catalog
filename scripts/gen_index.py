#!/usr/bin/env python3
"""Generate catalog/index.json from catalog/threats.json.

Produces a lightweight hierarchy summary for frontend/CLI consumption.
"""

import json
import os
import re

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
THREATS_PATH = os.path.join(REPO_ROOT, "catalog", "threats.json")
INDEX_PATH = os.path.join(REPO_ROOT, "catalog", "index.json")


def slugify(name: str) -> str:
    """Convert a name to a slug: lowercase, spaces→underscores, &→and, /→_, strip non-alnum."""
    s = name.lower()
    s = s.replace("&", "and")
    s = s.replace("/", "_")
    s = s.replace(" ", "_")
    s = re.sub(r"[^a-z0-9_]", "", s)
    return s


def main():
    with open(THREATS_PATH) as f:
        catalog = json.load(f)

    attack_classes = []
    for ac in catalog["attack_classes"]:
        categories = []
        for cat in ac["categories"]:
            categories.append(
                {
                    "id": cat["id"],
                    "name": cat["name"],
                    "slug": slugify(cat["name"]),
                    "vector_count": len(cat["vectors"]),
                }
            )
        attack_classes.append(
            {
                "id": ac["id"],
                "name": ac["name"],
                "slug": slugify(ac["name"]),
                "owasp_refs": ac.get("owasp_refs", []),
                "categories": categories,
            }
        )

    index = {
        "version": catalog.get("version", "1.0.0"),
        "attack_classes": attack_classes,
    }

    with open(INDEX_PATH, "w") as f:
        json.dump(index, f, indent=2)
        f.write("\n")

    total_vectors = sum(
        cat["vector_count"] for ac in attack_classes for cat in ac["categories"]
    )
    print(
        f"Wrote {INDEX_PATH}: {len(attack_classes)} classes, "
        f"{sum(len(ac['categories']) for ac in attack_classes)} categories, "
        f"{total_vectors} vectors"
    )


if __name__ == "__main__":
    main()
