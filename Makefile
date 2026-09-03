# Build
GO_CMDS := pola polad
IMAGE   := pola
TAG     ?= latest

# Test
PYTHON_DIRS  := test
TEST_BIN_DIR := test/bin
PYTEST_ARGS  ?= -s

# Coverage
COVER_PKGS    := ./cmd/... ./internal/... ./pkg/...
COVER_PROFILE := coverage.out
DIFF_BASE      ?= origin/develop
DIFF_COVER_MIN ?= 90

# External dependencies
GOBGP_CMDS    := gobgp gobgpd
GOBGP_MODULE  := github.com/osrg/gobgp/v4
GOBGP_VERSION := $(shell go list -m -f '{{.Version}}' $(GOBGP_MODULE))

# Go tools are pinned in go.mod.
MARKDOWNLINT_VERSION ?= 0.49.1
RUFF_VERSION         ?= 0.16.3

LICENSES_TEMPLATE := licenses/report.md.tmpl
LICENSES_OUTPUT   := licenses/THIRD_PARTY_LICENSES.md

.PHONY: \
	help \
	setup \
	fmt \
	fix \
	lint \
	lint-go \
	lint-proto \
	lint-python \
	lint-markdown \
	lint-actions \
	vuln \
	proto \
	check-proto \
	build \
	install \
	test \
	test-examples \
	test-race \
	test-coverage \
	test-coverage-html \
	test-coverage-diff \
	image \
	image-debug \
	licenses \
	check-licenses \
	fetch-gobgp \
	test-deps \
	test-scenario \
	test-scenario-parallel \
	ci \
	release \
	clean

.DEFAULT_GOAL := build

help: ## Show available targets
	@grep -E '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | \
	awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-22s\033[0m %s\n", $$1, $$2}'

# Print a Makefile variable's value, e.g. `make print-RUFF_VERSION`.
print-%:
	@echo $($*)

setup: ## Install development tools required by this Makefile
	@command -v go >/dev/null || (echo "Go is required: https://go.dev/dl/"; exit 1)
	@command -v npm >/dev/null || (echo "npm is required (tested with npm 11.17.0): https://nodejs.org/"; exit 1)
	@command -v uv >/dev/null || (echo "uv is required (tested with uv 0.12.0): https://docs.astral.sh/uv/getting-started/installation/"; exit 1)
	npm install -g markdownlint-cli@$(MARKDOWNLINT_VERSION)
	uv tool install ruff@$(RUFF_VERSION)
	@echo ""
	@echo "Setup complete. Make sure this is in your PATH:"
	@echo "  $$(npm config get prefix)/bin"
	@echo ""
	@echo "Also required but not installed by this target:"
	@echo "  - Docker (for 'image', 'image-debug', and 'test-scenario')"
	@echo "  - containerlab (https://containerlab.dev/install/, for 'test-scenario')"

fmt: ## Format Go and Python source code
	go tool golangci-lint fmt
	ruff format $(PYTHON_DIRS)

fix: fmt ## Apply automatic fixes
	go fix ./...
	go tool golangci-lint run --fix --config=.golangci.yml
	ruff check --fix $(PYTHON_DIRS)
	go tool pinact run -u

lint: lint-go lint-proto lint-python lint-markdown lint-actions ## Run every linter

lint-go: ## Lint Go code
	go tool golangci-lint run --config=.golangci.yml

lint-proto: ## Lint protobuf definitions
	buf lint

lint-python: ## Lint and format-check Python code
	ruff check $(PYTHON_DIRS)
	ruff format --check $(PYTHON_DIRS)

lint-markdown: ## Lint Markdown
	markdownlint '**/*.md' --ignore node_modules

# Verify SHA pins and their version comments without modifying workflows.
lint-actions: ## Verify GitHub Actions are pinned to commit SHAs
	go tool pinact run --check --verify

vuln: ## Report known vulnerabilities in dependencies
	go tool govulncheck ./...

proto: ## Generate protobuf code
	buf generate

check-proto: proto ## Verify generated protobuf code is up to date
	git diff --exit-code -- '*.pb.go' '*_grpc.pb.go'
	test -z "$$(git ls-files --others --exclude-standard -- '*.pb.go' '*_grpc.pb.go')"

build: ## Build Go binaries
	mkdir -p bin
	@for cmd in $(GO_CMDS); do \
		go build -o bin/$$cmd ./cmd/$$cmd; \
	done

install: ## Install Go binaries into GOPATH/bin
	@for cmd in $(GO_CMDS); do \
		go install ./cmd/$$cmd; \
	done

test: ## Run Go unit tests
	go test ./...

test-examples: ## Run Go unit tests for the examples module
	cd examples && go test ./...

test-race: ## Run Go unit tests with race detector
	go test -race ./...

test-coverage: ## Run Go unit tests and print a coverage summary
	go test $(COVER_PKGS) -coverprofile=$(COVER_PROFILE)
	go tool cover -func=$(COVER_PROFILE)

test-coverage-html: test-coverage ## Open the coverage report in a browser
	go tool cover -html=$(COVER_PROFILE)

test-coverage-diff: test-coverage ## Check coverage of changed lines
	go run ./tools/coverage-diff \
		-base=$(DIFF_BASE) \
		-profile=$(COVER_PROFILE) \
		-min=$(DIFF_COVER_MIN)

image: ## Build production Docker image
	docker buildx build \
		-t $(IMAGE):$(TAG) \
		-f build/package/Dockerfile \
		--load \
		.

image-debug: ## Build debug Docker image (adds a shell and network tools)
	docker buildx build \
		-t $(IMAGE):$(TAG)-debug \
		-f build/package/Dockerfile.debug \
		--load \
		.

licenses: ## Generate third-party license file
	go tool go-licenses report --include_tests --ignore $(shell go list -m) \
		--template=$(LICENSES_TEMPLATE) ./... > $(LICENSES_OUTPUT)

check-licenses: licenses ## Verify third-party license file is up to date
	git diff --exit-code -- $(LICENSES_OUTPUT)

fetch-gobgp: ## Fetch gobgp/gobgpd binaries into test/bin
	mkdir -p $(TEST_BIN_DIR)
	@for cmd in $(GOBGP_CMDS); do \
		CGO_ENABLED=0 GOBIN=$(abspath $(TEST_BIN_DIR)) go install $(GOBGP_MODULE)/cmd/$$cmd@$(GOBGP_VERSION); \
	done

test-deps: build fetch-gobgp ## Stage all binaries required for scenario tests
	mkdir -p $(TEST_BIN_DIR)
	@for cmd in $(GO_CMDS); do \
		cp bin/$$cmd $(TEST_BIN_DIR)/$$cmd; \
	done

test-scenario: test-deps ## Run containerlab scenario tests
	cd test && uv run pytest $(PYTEST_ARGS)

# Keep tests sharing a lab on the same worker.
test-scenario-parallel: PYTEST_ARGS = -s -n 4 --dist loadgroup
test-scenario-parallel: test-scenario ## Run containerlab scenario tests, one lab per worker

ci: check-proto check-licenses lint build test test-examples test-coverage-diff ## Run the same checks as CI

release: ## Cut a release: make release VERSION=X.Y.Z
	@if [ -z "$(VERSION)" ]; then echo "Usage: make release VERSION=X.Y.Z"; exit 1; fi
	@if ! echo "$(VERSION)" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$$'; then echo "VERSION must be in X.Y.Z format: $(VERSION)"; exit 1; fi
	@if [ -n "$$(git status --porcelain)" ]; then echo "Working tree is not clean"; exit 1; fi
	@if [ "$$(git rev-parse --abbrev-ref HEAD)" != "main" ]; then echo "Must be on main branch"; exit 1; fi
	@git fetch origin main develop --tags
	@if git rev-parse -q --verify "refs/tags/v$(VERSION)" >/dev/null; then \
		echo "Tag v$(VERSION) already exists"; exit 1; \
	fi
	@if [ "$$(git rev-parse HEAD)" != "$$(git rev-parse origin/main)" ]; then echo "Local main is out of sync with origin/main"; exit 1; fi
	@if [ -n "$$(git log origin/main..origin/develop --oneline)" ]; then \
		echo "develop has commits not yet merged into main:"; \
		git log origin/main..origin/develop --oneline; \
		exit 1; \
	fi
	$(MAKE) ci
	$(MAKE) test-race
	git tag -a "v$(VERSION)" -m "Release v$(VERSION)"
	git push origin "v$(VERSION)"

clean: ## Remove generated files
	$(RM) -r bin
	@find $(TEST_BIN_DIR) -type f ! -name .gitignore -delete 2>/dev/null || true
	$(RM) $(COVER_PROFILE)
