GO_CMDS               := pola polad
IMAGE                 := pola
TAG                   ?= latest
PYTHON_DIRS           := test
TEST_BIN_DIR          := test/bin
GOBGP_CMDS            := gobgp gobgpd
GOBGP_MODULE          := github.com/osrg/gobgp/v4
GOBGP_VERSION         := $(shell go list -m -f '{{.Version}}' $(GOBGP_MODULE))
GO_VERSION            := $(shell go list -m -f '{{.GoVersion}}')
GOLANGCI_LINT_VERSION ?= latest
BUF_VERSION           ?= latest
PINACT_VERSION        ?= latest
MARKDOWNLINT_VERSION  ?= latest
RUFF_VERSION          ?= latest
PYTEST_ARGS           ?= -s

.PHONY: \
	help \
	setup \
	build \
	install \
	fmt \
	fix \
	lint \
	test \
	test-race \
	proto \
	check-proto \
	image \
	image-dev \
	fetch-gobgp \
	test-deps \
	test-scenario \
	ci \
	clean

.DEFAULT_GOAL := build

help: ## Show available targets
	@grep -E '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | \
	awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-16s\033[0m %s\n", $$1, $$2}'

setup: ## Install development tools required by this Makefile
	@command -v go >/dev/null || (echo "Go is required: https://go.dev/dl/"; exit 1)
	@command -v npm >/dev/null || (echo "npm is required (tested with npm 11.17.0): https://nodejs.org/"; exit 1)
	@command -v uv >/dev/null || (echo "uv is required (tested with uv 0.12.0): https://docs.astral.sh/uv/getting-started/installation/"; exit 1)
	GOTOOLCHAIN=go$(GO_VERSION) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	GOTOOLCHAIN=go$(GO_VERSION) go install github.com/bufbuild/buf/cmd/buf@$(BUF_VERSION)
	GOTOOLCHAIN=go$(GO_VERSION) go install github.com/suzuki-shunsuke/pinact/cmd/pinact@$(PINACT_VERSION)
	npm install -g markdownlint-cli@$(MARKDOWNLINT_VERSION)
	uv tool install ruff@$(RUFF_VERSION)
	@echo ""
	@echo "Setup complete. Make sure these are in your PATH:"
	@echo "  $$(go env GOPATH)/bin"
	@echo "  $$(npm config get prefix)/bin"
	@echo ""
	@echo "Also required but not installed by this target:"
	@echo "  - Docker (for 'image', 'image-dev', and 'test-scenario')"
	@echo "  - containerlab (https://containerlab.dev/install/, for 'test-scenario')"

build: ## Build Go binaries
	mkdir -p bin
	@for cmd in $(GO_CMDS); do \
		go build -o bin/$$cmd ./cmd/$$cmd; \
	done

install: ## Install Go binaries into GOPATH/bin
	@for cmd in $(GO_CMDS); do \
		go install ./cmd/$$cmd; \
	done

fmt: ## Format Go and Python source code
	go fmt ./...
	ruff format $(PYTHON_DIRS)

fix: fmt ## Apply automatic fixes
	golangci-lint run --fix --config=.golangci.yml
	ruff check --fix $(PYTHON_DIRS)
	pinact run -u

lint: ## Run linters
	test -z "$$(gofmt -l .)"
	golangci-lint run --config=.golangci.yml
	buf lint
	ruff check $(PYTHON_DIRS)
	ruff format --check $(PYTHON_DIRS)
	markdownlint '**/*.md' --ignore node_modules
	pinact run

test: ## Run Go unit tests
	go test ./...

test-race: ## Run Go unit tests with race detector
	go test -race ./...

proto: ## Generate protobuf code
	buf generate

check-proto: proto ## Verify generated protobuf code is up to date
	git diff --exit-code -- '*.pb.go' '*_grpc.pb.go'
	test -z "$$(git ls-files --others --exclude-standard -- '*.pb.go' '*_grpc.pb.go')"

image: ## Build production Docker image
	docker buildx build \
		-t $(IMAGE):$(TAG) \
		-f build/package/Dockerfile \
		--load \
		.

image-dev: ## Build development Docker image
	docker buildx build \
		-t $(IMAGE):$(TAG)-dev \
		-f build/package/Dockerfile.dev \
		--load \
		.

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

ci: build check-proto lint test ## Run the same checks as CI

clean: ## Remove generated files
	$(RM) -r bin $(TEST_BIN_DIR)
