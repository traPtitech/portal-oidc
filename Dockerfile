# syntax=docker/dockerfile:1

# ============================================================================
# Base stage: Common setup for all stages
# ============================================================================
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS base

WORKDIR /app

# ============================================================================
# Development stage: Hot-reload with Air
# ============================================================================
FROM base AS development

# renovate: datasource=github-releases depName=air-verse/air
ARG AIR_VERSION=v1.63.0
RUN go install github.com/air-verse/air@${AIR_VERSION}

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

EXPOSE 8080

CMD ["air", "-c", ".air.toml"]

# ============================================================================
# Builder stage: Compile the application
# ============================================================================
FROM base AS builder

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
ARG TARGETOS
ARG TARGETARCH

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build \
    -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
    -o /out/portal-oidc \
    ./cmd

# ============================================================================
# Data stage: scaffold /app/data writable by the nonroot runtime user
# ============================================================================
FROM alpine:3.21 AS data
RUN mkdir -p /out/data && chown -R 65532:65532 /out/data && chmod 700 /out/data

# ============================================================================
# Production stage: Distroless runtime image
# ============================================================================
FROM gcr.io/distroless/static-debian12:nonroot AS production

LABEL org.opencontainers.image.title="portal-oidc" \
      org.opencontainers.image.description="traP Portal OIDC Provider" \
      org.opencontainers.image.source="https://github.com/traPtitech/portal-oidc" \
      org.opencontainers.image.vendor="traP" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app

COPY --from=builder --chown=65532:65532 /out/portal-oidc /app/portal-oidc
COPY --from=data    --chown=65532:65532 /out/data        /app/data

USER 65532:65532

EXPOSE 8080

ENTRYPOINT ["/app/portal-oidc"]
CMD ["serve"]
