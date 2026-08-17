SHELL := /bin/bash

REMOTE ?= origin
TAG_PREFIX ?= v

.PHONY: test build snapshot next-tag release

test:
	go test ./...

build:
	go build -o net-peek .

snapshot:
	@rm -rf dist/package
	@mkdir -p dist/package
	go build -trimpath -o dist/package/net-peek .
	@cp README.md dist/package/
	@if compgen -G "LICENSE*" > /dev/null; then cp LICENSE* dist/package/; fi
	@tar -czf "dist/net-peek_snapshot_$$(go env GOOS)_$$(go env GOARCH).tar.gz" -C dist/package .

next-tag:
	@$(MAKE) --no-print-directory _next_tag

release:
	@test -z "$$(git status --porcelain)" || { echo "working tree is not clean"; exit 1; }
	@git fetch --tags $(REMOTE)
	@latest_tag="$$(git tag --list '$(TAG_PREFIX)[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname | head -n 1)"; \
		if [[ -z "$$latest_tag" ]]; then \
			next_tag="$(TAG_PREFIX)0.1.0"; \
		else \
			version="$${latest_tag#$(TAG_PREFIX)}"; \
			IFS=. read -r major minor patch <<< "$$version"; \
			next_tag="$(TAG_PREFIX)$${major}.$${minor}.$$((patch + 1))"; \
		fi; \
		echo "creating release $$next_tag"; \
		git tag -a "$$next_tag" -m "$$next_tag"; \
		git push $(REMOTE) "$$next_tag"

_next_tag:
	@git fetch --tags $(REMOTE) >/dev/null
	@latest_tag="$$(git tag --list '$(TAG_PREFIX)[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname | head -n 1)"; \
		if [[ -z "$$latest_tag" ]]; then \
			echo "$(TAG_PREFIX)0.1.0"; \
		else \
			version="$${latest_tag#$(TAG_PREFIX)}"; \
			IFS=. read -r major minor patch <<< "$$version"; \
			echo "$(TAG_PREFIX)$${major}.$${minor}.$$((patch + 1))"; \
		fi
