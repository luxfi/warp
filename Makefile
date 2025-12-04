# Warp V2 Makefile
# Cross-chain messaging protocol implementation

.PHONY: all build test clean install proto lint fmt release help

# Variables
GOPATH := $(shell go env GOPATH)
GOBIN := $(GOPATH)/bin
BINARY_NAME := warp
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_DATE := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.buildDate=$(BUILD_DATE)"
GO_FILES := $(shell find . -name '*.go' -not -path './vendor/*' -not -path './build/*')
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

# Build flags
GO_BUILD_FLAGS := -v
GO_TEST_FLAGS := -v -race -coverprofile=coverage.txt -covermode=atomic

# Installation paths
INSTALL_PREFIX ?= /usr/local
CLI_PLUGIN_PATH := $(HOME)/work/lux/cli/pkg/warp

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[0;33m
NC := \033[0m # No Color

# Default target
all: clean build test

# Build the library
build:
	@echo "$(GREEN)Building Warp library...$(NC)"
	@go build $(GO_BUILD_FLAGS) ./...
	@echo "$(GREEN)Build complete!$(NC)"

# Build example binary
build-example:
	@echo "$(GREEN)Building example binary...$(NC)"
	@go build $(GO_BUILD_FLAGS) $(LDFLAGS) -o build/$(BINARY_NAME)-example ./example
	@echo "$(GREEN)Example binary built: build/$(BINARY_NAME)-example$(NC)"

# Build CLI tool
build-cli:
	@echo "$(GREEN)Building Warp CLI tool...$(NC)"
	@mkdir -p build
	@go build $(GO_BUILD_FLAGS) $(LDFLAGS) -o build/$(BINARY_NAME)-cli ./cmd/warpcli
	@echo "$(GREEN)CLI tool built: build/$(BINARY_NAME)-cli$(NC)"

# Run tests
test:
	@echo "$(GREEN)Running tests...$(NC)"
	@go test $(GO_TEST_FLAGS) ./...
	@echo "$(GREEN)Tests complete!$(NC)"

# Run tests with coverage
test-coverage:
	@echo "$(GREEN)Running tests with coverage...$(NC)"
	@go test $(GO_TEST_FLAGS) ./...
	@go tool cover -html=coverage.txt -o coverage.html
	@echo "$(GREEN)Coverage report generated: coverage.html$(NC)"

# Run integration tests
test-integration:
	@echo "$(GREEN)Running integration tests...$(NC)"
	@go test $(GO_TEST_FLAGS) -tags=integration ./tests/integration/...

# Run benchmarks
bench:
	@echo "$(GREEN)Running benchmarks...$(NC)"
	@go test -bench=. -benchmem ./...

# Clean build artifacts
clean:
	@echo "$(YELLOW)Cleaning build artifacts...$(NC)"
	@rm -rf build/
	@rm -f coverage.txt coverage.html
	@go clean -cache
	@echo "$(GREEN)Clean complete!$(NC)"

# Install binary
install: build-cli
	@echo "$(GREEN)Installing Warp CLI...$(NC)"
	@mkdir -p $(INSTALL_PREFIX)/bin
	@cp build/$(BINARY_NAME)-cli $(INSTALL_PREFIX)/bin/$(BINARY_NAME)
	@chmod +x $(INSTALL_PREFIX)/bin/$(BINARY_NAME)
	@echo "$(GREEN)Installed to $(INSTALL_PREFIX)/bin/$(BINARY_NAME)$(NC)"

# Install as Lux CLI plugin
install-plugin:
	@echo "$(GREEN)Installing as Lux CLI plugin...$(NC)"
	@mkdir -p $(CLI_PLUGIN_PATH)
	@cp -r cmd/plugin/* $(CLI_PLUGIN_PATH)/
	@echo "$(GREEN)Plugin installed to $(CLI_PLUGIN_PATH)$(NC)"

# Format code
fmt:
	@echo "$(GREEN)Formatting code...$(NC)"
	@go fmt ./...
	@gofmt -s -w $(GO_FILES)
	@echo "$(GREEN)Code formatted!$(NC)"

# Lint code
lint:
	@echo "$(GREEN)Linting code...$(NC)"
	@if ! which golangci-lint > /dev/null; then \
		echo "$(YELLOW)Installing golangci-lint v2...$(NC)"; \
		go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.1.6; \
	fi
	@golangci-lint run --timeout=5m
	@echo "$(GREEN)Linting complete!$(NC)"

# Generate protocol buffers
proto:
	@echo "$(GREEN)Generating protocol buffers...$(NC)"
	@if ! which protoc > /dev/null; then \
		echo "$(RED)Error: protoc not found. Please install protocol buffers compiler.$(NC)"; \
		exit 1; \
	fi
	@protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		protocol/*.proto
	@echo "$(GREEN)Protocol buffers generated!$(NC)"

# Check dependencies
check-deps:
	@echo "$(GREEN)Checking dependencies...$(NC)"
	@go mod verify
	@go mod tidy
	@echo "$(GREEN)Dependencies verified!$(NC)"

# Security scan
security:
	@echo "$(GREEN)Running security scan...$(NC)"
	@if ! which gosec > /dev/null; then \
		echo "$(YELLOW)Installing gosec...$(NC)"; \
		go install github.com/securego/gosec/v2/cmd/gosec@latest; \
	fi
	@gosec -fmt=json -out=security-report.json ./... || true
	@echo "$(GREEN)Security scan complete! Report: security-report.json$(NC)"

# Build for multiple platforms
release:
	@echo "$(GREEN)Building releases for multiple platforms...$(NC)"
	@mkdir -p build/release
	@for platform in $(PLATFORMS); do \
		GOOS=$$(echo $$platform | cut -d'/' -f1); \
		GOARCH=$$(echo $$platform | cut -d'/' -f2); \
		output="build/release/$(BINARY_NAME)-$$GOOS-$$GOARCH"; \
		if [ "$$GOOS" = "windows" ]; then output="$$output.exe"; fi; \
		echo "Building for $$GOOS/$$GOARCH..."; \
		GOOS=$$GOOS GOARCH=$$GOARCH go build $(GO_BUILD_FLAGS) $(LDFLAGS) -o $$output ./cmd/warpcli; \
	done
	@echo "$(GREEN)Release builds complete!$(NC)"

# Create release archives
release-archives: release
	@echo "$(GREEN)Creating release archives...$(NC)"
	@cd build/release && for file in $(BINARY_NAME)-*; do \
		if [ -f "$$file" ]; then \
			tar czf "$$file.tar.gz" "$$file"; \
			echo "Created $$file.tar.gz"; \
		fi; \
	done
	@echo "$(GREEN)Release archives created!$(NC)"

# Run development server (for testing)
dev:
	@echo "$(GREEN)Running in development mode...$(NC)"
	@go run ./cmd/warpcli serve --dev

# Docker build
docker-build:
	@echo "$(GREEN)Building Docker image...$(NC)"
	@docker build -t warp:$(VERSION) -t warp:latest .
	@echo "$(GREEN)Docker image built!$(NC)"

# Generate documentation
docs:
	@echo "$(GREEN)Generating documentation...$(NC)"
	@if ! which godoc > /dev/null; then \
		echo "$(YELLOW)Installing godoc...$(NC)"; \
		go install golang.org/x/tools/cmd/godoc@latest; \
	fi
	@godoc -http=:6060 &
	@echo "$(GREEN)Documentation server started at http://localhost:6060$(NC)"

# CI/CD targets
ci: clean check-deps lint test test-coverage security

# Performance profiling
profile:
	@echo "$(GREEN)Running CPU profiling...$(NC)"
	@go test -cpuprofile=cpu.prof -memprofile=mem.prof -bench=.
	@echo "$(GREEN)Profiling complete! Use 'go tool pprof' to analyze.$(NC)"

# Help target
help:
	@echo "$(GREEN)Warp V2 Makefile$(NC)"
	@echo ""
	@echo "Available targets:"
	@echo "  $(YELLOW)all$(NC)              - Clean, build, and test"
	@echo "  $(YELLOW)build$(NC)            - Build the library"
	@echo "  $(YELLOW)build-example$(NC)    - Build example binary"
	@echo "  $(YELLOW)build-cli$(NC)        - Build CLI tool"
	@echo "  $(YELLOW)test$(NC)             - Run tests"
	@echo "  $(YELLOW)test-coverage$(NC)    - Run tests with coverage report"
	@echo "  $(YELLOW)test-integration$(NC) - Run integration tests"
	@echo "  $(YELLOW)bench$(NC)            - Run benchmarks"
	@echo "  $(YELLOW)clean$(NC)            - Clean build artifacts"
	@echo "  $(YELLOW)install$(NC)          - Install CLI binary"
	@echo "  $(YELLOW)install-plugin$(NC)   - Install as Lux CLI plugin"
	@echo "  $(YELLOW)fmt$(NC)              - Format code"
	@echo "  $(YELLOW)lint$(NC)             - Lint code"
	@echo "  $(YELLOW)proto$(NC)            - Generate protocol buffers"
	@echo "  $(YELLOW)check-deps$(NC)       - Check and tidy dependencies"
	@echo "  $(YELLOW)security$(NC)         - Run security scan"
	@echo "  $(YELLOW)release$(NC)          - Build for multiple platforms"
	@echo "  $(YELLOW)release-archives$(NC) - Create release archives"
	@echo "  $(YELLOW)docker-build$(NC)     - Build Docker image"
	@echo "  $(YELLOW)docs$(NC)             - Generate documentation"
	@echo "  $(YELLOW)ci$(NC)               - Run CI pipeline"
	@echo "  $(YELLOW)profile$(NC)          - Run performance profiling"
	@echo "  $(YELLOW)help$(NC)             - Show this help message"