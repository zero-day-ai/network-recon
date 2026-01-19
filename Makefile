# Network Recon Agent Makefile
# A lightweight network reconnaissance agent for basic network discovery tasks

.PHONY: all build bin test test-race test-coverage lint fmt vet tidy clean deps check run install help

# Build configuration
BINARY_NAME=network-recon
GO=go
GOFLAGS=-v

# Version management (optional - uncomment if using VERSION file)
# VERSION=$(shell cat VERSION 2>/dev/null || echo "0.0.0-dev")
# GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
# BUILD_DATE=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
# LDFLAGS=-ldflags="-s -w -X main.version=$(VERSION) -X main.commit=$(GIT_COMMIT) -X main.date=$(BUILD_DATE)"

# Default target
.DEFAULT_GOAL := help

## help: Display this help message
help:
	@echo "Network Recon Agent - Makefile targets:"
	@echo ""
	@grep -E '^##' $(MAKEFILE_LIST) | sed -e 's/## /  /'
	@echo ""

## all: Run tests and build (default)
all: test build

## build: Build the network-recon binary
build:
	@echo "Building $(BINARY_NAME)..."
	$(GO) build $(GOFLAGS) -o $(BINARY_NAME) .
	@echo "Build complete: $(BINARY_NAME)"

## bin: Alias for build
bin: build

## test: Run all tests
test:
	@echo "Running tests..."
	$(GO) test -v ./...
	@echo "Tests complete"

## test-race: Run tests with race detection
test-race:
	@echo "Running tests with race detection..."
	$(GO) test -race -v ./...

## test-coverage: Run tests with coverage report
test-coverage:
	@echo "Running tests with coverage..."
	$(GO) test -coverprofile=coverage.out -covermode=atomic ./...
	@echo "Coverage report:"
	@$(GO) tool cover -func=coverage.out

## coverage-html: Generate HTML coverage report
coverage-html: test-coverage
	@$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage HTML report: coverage.html"

## lint: Run linters (golangci-lint)
lint:
	@echo "Running linters..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not found. Install: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
		exit 1; \
	fi
	@echo "Linting complete"

## fmt: Format Go code
fmt:
	@echo "Formatting code..."
	$(GO) fmt ./...
	@echo "Formatting complete"

## vet: Run go vet
vet:
	@echo "Running go vet..."
	$(GO) vet ./...
	@echo "Vet complete"

## tidy: Tidy go modules
tidy:
	@echo "Tidying modules..."
	$(GO) mod tidy

## clean: Remove build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(BINARY_NAME)
	rm -f coverage.out coverage.html
	$(GO) clean -cache -testcache
	@echo "Clean complete"

## deps: Download and tidy dependencies
deps:
	@echo "Downloading dependencies..."
	$(GO) mod download
	$(GO) mod tidy
	@echo "Dependencies updated"

## check: Run all checks (fmt, vet, lint, test)
check: fmt vet lint test
	@echo "All checks passed!"

## verify: Alias for check
verify: check

## run: Build and run the agent
run: build
	@echo "Running $(BINARY_NAME)..."
	./$(BINARY_NAME)

## install: Install to Gibson agents directory
install: build
	@echo "Installing $(BINARY_NAME) to ~/.gibson/agents/bin/..."
	@mkdir -p ~/.gibson/agents/bin
	cp $(BINARY_NAME) ~/.gibson/agents/bin/
	@echo "Install complete"

## install-gopath: Install to GOPATH/bin
install-gopath: build
	@echo "Installing $(BINARY_NAME) to GOPATH/bin..."
	$(GO) install .
	@echo "Install complete"
