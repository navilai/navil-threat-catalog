.PHONY: validate update release help

help:
	@echo "navil-threat-catalog"
	@echo ""
	@echo "  make validate        Run schema validation on threats.json"
	@echo "  make update FILE=threat-catalog-candidates-YYYY-MM-DD.md   Merge approved vectors"
	@echo "  make release VERSION=v1.0.1   Tag and push a new release"

validate:
	python3 scripts/validate.py

update:
	@if [ -z "$(FILE)" ]; then echo "Usage: make update FILE=path/to/candidates.md"; exit 1; fi
	python3 scripts/merge_candidates.py "$(FILE)"
	python3 scripts/validate.py
	python3 scripts/sync_yaml.py

release:
	@if [ -z "$(VERSION)" ]; then echo "Usage: make release VERSION=v1.x.x"; exit 1; fi
	git add catalog/ mappings/ README.md
	git commit -m "release: $(VERSION)"
	gh release create $(VERSION) --title "$(VERSION)" --generate-notes
	git push
