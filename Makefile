REPO := dsiganos/pkitree

.PHONY: help pages-status pages-url open lint commit deploy refresh-cas

help:
	@grep -E '^[a-zA-Z_-]+:.*?##' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-16s %s\n", $$1, $$2}'

pages-status: ## Show GitHub Pages deployment status
	gh api repos/$(REPO)/pages --jq '.html_url, .status'

pages-url: ## Print the GitHub Pages URL
	@gh api repos/$(REPO)/pages --jq '.html_url'

open: ## Open the live GitHub Pages site in a browser
	xdg-open $$(gh api repos/$(REPO)/pages --jq '.html_url')

lint: ## Validate HTML with vnu (requires vnu-jar or npx vnu)
	@if command -v vnu >/dev/null 2>&1; then \
		vnu index.html; \
	elif command -v npx >/dev/null 2>&1; then \
		npx --yes vnu index.html; \
	else \
		echo "vnu not found — install with: npm install -g vnu-jar"; exit 1; \
	fi

serve: ## Serve locally on http://localhost:8080
	@python3 -m http.server 8080 --directory .

commit: ## Stage index.html, get AI commit message, edit, then commit
	@if [ -z "$$(git status --porcelain index.html)" ]; then \
		echo "Nothing to commit."; \
	else \
		TMPFILE=$$(mktemp); \
		git diff index.html | claude -p "Write a concise git commit message for this diff. Reply with only the message, no explanation or markdown." > $$TMPFILE; \
		git add index.html && git commit -t $$TMPFILE; \
		rm -f $$TMPFILE; \
	fi

refresh-cas: ## Refresh roots.pem + intermediates.pem from Mozilla data
	curl -sf https://curl.se/ca/cacert.pem -o roots.pem
	curl -sf https://firefox-settings-attachments.cdn.mozilla.net/bundles/security-state--intermediates.zip -o /tmp/rs-intermediates.zip
	python3 -c "import zipfile; z=zipfile.ZipFile('/tmp/rs-intermediates.zip'); \
	pems=[z.read(n).decode('utf-8','replace').strip() for n in z.namelist() if not n.endswith('.meta.json')]; \
	pems=[p for p in pems if 'BEGIN CERTIFICATE' in p]; \
	open('intermediates.pem','w').write('\n'.join(pems)+'\n'); print('intermediates:',len(pems))"
	@grep -c "BEGIN CERTIFICATE" roots.pem intermediates.pem

deploy: ## Push and wait for GitHub Pages to build this exact commit
	git push
	@sha=$$(git rev-parse HEAD); \
	echo "Waiting for Pages to build $$sha..."; \
	for i in $$(seq 1 24); do \
		out=$$(gh api repos/$(REPO)/pages/builds/latest --jq '.commit + " " + .status' 2>/dev/null); \
		echo "  $$out"; \
		case "$$out" in \
			"$$sha built")   echo "Deployed."; exit 0;; \
			"$$sha errored") echo "Pages build FAILED."; exit 1;; \
		esac; \
		sleep 5; \
	done; \
	echo "Timed out waiting for Pages to build $$sha"; exit 1
