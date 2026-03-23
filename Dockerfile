# =============================================================================
# Stage 1: Build Go engine
# =============================================================================
FROM golang:1.24-alpine AS engine-builder

WORKDIR /build

# Download dependencies first (cached layer)
COPY engine/go.mod engine/go.sum ./
RUN go mod download

# Build engine binary (static, stripped)
COPY engine/ .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /securepdf-engine ./cmd/securepdf-engine

# =============================================================================
# Stage 2: Python runtime (final image)
# =============================================================================
FROM python:3.11-alpine AS runtime

LABEL org.opencontainers.image.source=https://github.com/ravishtiwari/pdf-secure
LABEL org.opencontainers.image.description="SecurePDF — PDF encryption, labeling, and provenance tracking"
LABEL org.opencontainers.image.licenses=MIT

# Copy Go engine binary from builder stage
COPY --from=engine-builder /securepdf-engine /usr/local/bin/securepdf-engine

# Install Python SDK
WORKDIR /app
COPY python/ .
RUN pip install --no-cache-dir -e . && \
    rm -rf /root/.cache/pip

# Smoke test — verifies both the binary and SDK are functional
RUN securepdf-engine --help > /dev/null && python -m securepdf --version

ENTRYPOINT ["python", "-m", "securepdf"]
CMD ["--help"]
