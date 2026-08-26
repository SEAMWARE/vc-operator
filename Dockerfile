# Build the manager binary
FROM golang:1.25 AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace

# Copy the Go Modules manifests first to leverage Docker layer caching.
# Dependencies are re-downloaded only when go.mod or go.sum change.
COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download

# Copy the Go source (relies on .dockerignore to filter).
COPY . .

# Build a statically linked binary for the target platform.
# CGO is disabled so the binary has no C library dependency,
# making it safe to run on a distroless base image.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o manager cmd/main.go

# Runtime stage: use distroless for a minimal, secure container image.
# The distroless/static image contains no shell or package manager,
# reducing the attack surface. See https://github.com/GoogleContainerTools/distroless
FROM gcr.io/distroless/static:nonroot

LABEL org.opencontainers.image.source="https://github.com/SEAMWARE/vc-operator"
LABEL org.opencontainers.image.description="VC Operator - Kubernetes operator for Verifiable Credentials via OID4VCI"
LABEL org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /
COPY --from=builder /workspace/manager .

# Run as non-root user (65532 is the nonroot user in distroless).
USER 65532:65532

ENTRYPOINT ["/manager"]
