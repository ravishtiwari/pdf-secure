SHELL := /bin/bash

.PHONY: help fmt lint test

help:
	@echo "Targets:"
	@echo "  fmt   - format Go/Python code"
	@echo "  lint  - run linters"
	@echo "  test  - run tests"

fmt:
	@cd engine && gofmt -l -w .
	@cd python && ruff check --fix . || true

lint:
	@cd engine && go vet ./...
	@cd python && ruff check .

test:
	@cd engine && go clean -testcache && go clean  && go test ./...
	@cd python && python3 -m pytest tests/ -v
