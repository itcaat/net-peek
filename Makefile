SHELL := /bin/bash

REMOTE ?= origin
TAG_PREFIX ?= v

.PHONY: test build snapshot next-tag next-beta beta release

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

next-beta:
	@$(MAKE) --no-print-directory _next_beta_tag

release:
	@test -z "$$(git status --porcelain)" || { echo "working tree is not clean"; exit 1; }
	@git fetch --tags $(REMOTE)
	@latest_tag="$$(git tag --list '$(TAG_PREFIX)[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname | grep -E '^$(TAG_PREFIX)[0-9]+\.[0-9]+\.[0-9]+$$' | head -n 1)"; \
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

beta:
	@test -z "$$(git status --porcelain)" || { echo "working tree is not clean"; exit 1; }
	@git fetch --tags $(REMOTE)
	@next_tag="$$($(MAKE) --no-print-directory _next_beta_tag)"; \
		echo "creating beta release $$next_tag"; \
		git tag -a "$$next_tag" -m "$$next_tag"; \
		git push $(REMOTE) "$$next_tag"

_next_tag:
	@git fetch --tags $(REMOTE) >/dev/null
	@latest_tag="$$(git tag --list '$(TAG_PREFIX)[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname | grep -E '^$(TAG_PREFIX)[0-9]+\.[0-9]+\.[0-9]+$$' | head -n 1)"; \
		if [[ -z "$$latest_tag" ]]; then \
			echo "$(TAG_PREFIX)0.1.0"; \
		else \
			version="$${latest_tag#$(TAG_PREFIX)}"; \
			IFS=. read -r major minor patch <<< "$$version"; \
			echo "$(TAG_PREFIX)$${major}.$${minor}.$$((patch + 1))"; \
		fi

_next_beta_tag:
	@git fetch --tags $(REMOTE) >/dev/null
	@latest_stable="$$(git tag --list '$(TAG_PREFIX)[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname | grep -E '^$(TAG_PREFIX)[0-9]+\.[0-9]+\.[0-9]+$$' | head -n 1)"; \
		if [[ -z "$$latest_stable" ]]; then \
			base="$(TAG_PREFIX)0.1.0"; \
		else \
			version="$${latest_stable#$(TAG_PREFIX)}"; \
			IFS=. read -r major minor patch <<< "$$version"; \
			base="$(TAG_PREFIX)$${major}.$${minor}.$$((patch + 1))"; \
		fi; \
		latest_beta="$$(git tag --list "$${base}-beta.*" --sort=-v:refname | head -n 1)"; \
		if [[ -z "$$latest_beta" ]]; then \
			echo "$${base}-beta.1"; \
		else \
			beta="$${latest_beta##*.}"; \
			echo "$${base}-beta.$$((beta + 1))"; \
		fi
