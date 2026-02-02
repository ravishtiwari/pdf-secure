SHELL := /bin/bash

.PHONY: help fmt lint test engine-clean-build \
        go-unit-tests go-e2e-tests go-all-tests \
        py-unit-tests py-e2e-tests py-all-tests \
        unit-tests e2e-tests all-tests

help:
	@echo "Targets:"
	@echo "  fmt              - format Go/Python code"
	@echo "  lint             - run linters"
	@echo "  test             - run all tests (legacy)"
	@echo ""
	@echo "Test Targets:"
	@echo "  unit-tests       - run all unit tests (Go + Python)"
	@echo "  e2e-tests        - run all E2E tests (Go + Python)"
	@echo "  all-tests        - run all tests (unit + E2E)"
	@echo ""
	@echo "Go Tests:"
	@echo "  go-unit-tests    - run Go unit tests"
	@echo "  go-e2e-tests     - run Go E2E tests"
	@echo "  go-all-tests     - run all Go tests"
	@echo ""
	@echo "Python Tests:"
	@echo "  py-unit-tests    - run Python unit tests"
	@echo "  py-e2e-tests     - run Python E2E tests"
	@echo "  py-all-tests     - run all Python tests"

fmt:
	@cd engine && gofmt -l -w .
	@cd python && ruff check --fix . || true

lint:
	@cd engine && go vet ./...
	@cd python && ruff check .

test:
	@cd engine && go clean -testcache && go clean && go test ./...
	@source .venv/bin/activate && cd python && python -m pytest tests/ -v

engine-clean-build:
	@cd engine && go clean -cache -testcache && go build -o ../bin/securepdf-engine ./cmd/securepdf-engine

# =============================================================================
# Go Test Targets
# =============================================================================

go-unit-tests:
	@echo "==> Running Go unit tests..."
	@cd engine && go clean -testcache && go clean
	@cd engine && go test -v ./pkg/... -count=1

go-e2e-tests:
	@echo "==> Running Go E2E tests..."
	@cd engine && go clean -testcache && go clean
	@cd engine && go test -v ./cmd/... -run "E2E" -count=1
	@cd engine && go test -v ./pkg/pdf/... -run "E2E" -count=1

go-all-tests:
	@echo "==> Running all Go tests..."
	@cd engine && go clean -testcache && go clean
	@cd engine && go test -v ./... -count=1

# =============================================================================
# Python Test Targets
# =============================================================================

py-unit-tests:
	@echo "==> Running Python unit tests..."
	@rm -rf python/.pytest_cache
	@source .venv/bin/activate && cd python && python -m pytest tests/ -v -k "not e2e"

py-e2e-tests:
	@echo "==> Running Python E2E tests..."
	@rm -rf python/.pytest_cache
	@source .venv/bin/activate && cd python && python -m pytest tests/ -v -k "e2e"

py-all-tests:
	@echo "==> Running all Python tests..."
	@rm -rf python/.pytest_cache
	@source .venv/bin/activate && cd python && python -m pytest tests/ -v

# =============================================================================
# Combined Test Targets
# =============================================================================

unit-tests: go-unit-tests py-unit-tests
	@echo "==> All unit tests complete!"

e2e-tests: go-e2e-tests py-e2e-tests
	@echo "==> All E2E tests complete!"

all-tests: go-all-tests py-all-tests
	@echo "==> All tests complete!"
