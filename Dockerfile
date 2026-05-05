# syntax=docker/dockerfile:1.7

# ============================================================================
# Base stage
# ============================================================================
FROM --platform=$BUILDPLATFORM golang:1.26.2-alpine@sha256:f85330846cde1e57ca9ec309382da3b8e6ae3ab943d2739500e08c86393a21b1 AS base

WORKDIR /app
ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=local \
    GOFLAGS=-mod=readonly

# ============================================================================
# Development stage: hot-reload with Air
# ============================================================================
FROM base AS development

# renovate: datasource=github-releases depName=air-verse/air
ARG AIR_VERSION=v1.63.0
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOFLAGS= go install github.com/air-verse/air@${AIR_VERSION}

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download && go mod verify

COPY . .

EXPOSE 8080

CMD ["air", "-c", ".air.toml"]

# ============================================================================
# Builder stage: compile the application
# ============================================================================
FROM base AS builder

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
ARG TARGETOS
ARG TARGETARCH

RUN --mount=type=bind,source=go.mod,target=go.mod \
    --mount=type=bind,source=go.sum,target=go.sum \
    --mount=type=cache,target=/go/pkg/mod \
    go mod download && go mod verify

RUN --mount=type=bind,target=. \
    --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build,id=gobuild-${TARGETOS}-${TARGETARCH} \
    GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build \
      -trimpath \
      -buildvcs=false \
      -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
      -o /out/portal-oidc \
      ./cmd

RUN mkdir -p /out/data && chown 65532:65532 /out/data && chmod 700 /out/data

# ============================================================================
# Production stage: distroless runtime image
# ============================================================================
FROM gcr.io/distroless/static-debian12:nonroot@sha256:a9329520abc449e3b14d5bc3a6ffae065bdde0f02667fa10880c49b35c109fd1 AS production

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

LABEL org.opencontainers.image.title="portal-oidc" \
      org.opencontainers.image.description="traP Portal OIDC Provider" \
      org.opencontainers.image.source="https://github.com/traPtitech/portal-oidc" \
      org.opencontainers.image.vendor="traP" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${BUILD_DATE}"

WORKDIR /app

COPY --from=builder --chown=65532:65532 /out/portal-oidc /app/portal-oidc
COPY --from=builder --chown=65532:65532 /out/data        /app/data

USER 65532:65532
STOPSIGNAL SIGTERM

EXPOSE 8080

ENTRYPOINT ["/app/portal-oidc"]
CMD ["serve"]
