# syntax=docker/dockerfile:1

# ============================================================================
# Base stage: Common setup for all stages
# ============================================================================
FROM golang:1.25-alpine AS base

WORKDIR /app

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
# Production stage: Distroless runtime image
# ============================================================================
FROM gcr.io/distroless/static-debian12:nonroot AS production

# OCI labels
LABEL org.opencontainers.image.title="portal-oidc" \
      org.opencontainers.image.description="traP Portal OIDC Provider" \
      org.opencontainers.image.source="https://github.com/traPtitech/portal-oidc" \
      org.opencontainers.image.vendor="traP" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app

# Copy the binary
COPY --from=builder /app/portal-oidc /app/portal-oidc

EXPOSE 8080

ENTRYPOINT ["/app/portal-oidc"]
CMD ["serve"]
