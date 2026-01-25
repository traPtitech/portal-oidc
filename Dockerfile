# syntax=docker/dockerfile:1

# ============================================================================
# Base stage: Common setup for all stages
# ============================================================================
FROM golang:1.25-alpine AS base

WORKDIR /app

# Install CA certificates for HTTPS and timezone data
RUN apk add --no-cache ca-certificates tzdata

# ============================================================================
# Development stage: Hot-reload with Air
# ============================================================================
FROM base AS development

# Install development tools
RUN go install github.com/air-verse/air@latest

# Copy dependency files first for better layer caching
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy source code (will be overwritten by volume mount in compose)
COPY . .

EXPOSE 8080

CMD ["air", "-c", ".air.toml"]

# ============================================================================
# Builder stage: Compile the application
# ============================================================================
FROM base AS builder

# Build arguments for versioning
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

# Copy dependency files first for better layer caching
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build static binary with optimizations
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
    -o /app/portal-oidc \
    ./cmd

# ============================================================================
# Production stage: Minimal runtime image
# ============================================================================
FROM scratch AS production

# OCI labels
LABEL org.opencontainers.image.title="portal-oidc" \
      org.opencontainers.image.description="traP Portal OIDC Provider" \
      org.opencontainers.image.source="https://github.com/traPtitech/portal-oidc" \
      org.opencontainers.image.vendor="traP" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app

# Copy CA certificates for HTTPS connections
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy timezone data
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy the binary
COPY --from=builder /app/portal-oidc /app/portal-oidc

# Use non-root user (numeric for scratch image compatibility)
USER 65534:65534

EXPOSE 8080

# Health check (requires curl in image, disabled for scratch)
# HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
#     CMD ["/app/portal-oidc", "health"]

ENTRYPOINT ["/app/portal-oidc"]
CMD ["serve"]
