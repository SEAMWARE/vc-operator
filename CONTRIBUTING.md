# Contributing to vc-operator

Thank you for your interest in contributing to the vc-operator! This document
provides guidelines and instructions for contributing.

## Prerequisites

- **Go 1.22+** -- The operator is written in Go. Install from
  [go.dev](https://go.dev/dl/).
- **Docker 17.03+** -- Required for building container images and running
  integration tests.
- **kubectl** -- Kubernetes CLI for interacting with clusters.
- **Make** -- Build automation. The project uses a Kubebuilder-generated
  Makefile.

The following tools are installed automatically by the Makefile on first use:

- **controller-gen** (v0.20.1) -- Generates CRD manifests, RBAC rules, and
  DeepCopy methods from Go types and kubebuilder markers.
- **kustomize** (v5.8.1) -- Kubernetes configuration management.
- **setup-envtest** -- Downloads Kubernetes API server binaries for integration
  tests.
- **golangci-lint** (v2.11.4) -- Go linter aggregator.

## Development Workflow

### Clone and Build

```bash
git clone https://github.com/SEAMWARE/vc-operator.git
cd vc-operator

# Run code generators (DeepCopy methods, CRD manifests)
make generate
make manifests

# Build the operator binary
make build
```

### Run Tests

```bash
# Run unit tests (uses envtest for Kubernetes API)
make test

# Run integration tests (requires Docker; uses envtest + mock OID4VCI issuer)
make test-integration

# Run linter
make lint
```

### Run Locally

To run the operator against a local or remote Kubernetes cluster:

```bash
# Install CRDs into the cluster
make install

# Run the operator locally (uses your current kubeconfig)
make run

# In another terminal, apply sample resources
kubectl apply -k config/samples/
```

### Build Container Image

```bash
# Build the Docker image
make docker-build IMG=my-registry/vc-operator:dev

# Push the image
make docker-push IMG=my-registry/vc-operator:dev

# Deploy to a cluster
make deploy IMG=my-registry/vc-operator:dev
```

## Project Structure

```
vc-operator/
+-- api/v1alpha1/              # CRD Go types with kubebuilder markers
+-- cmd/                       # Operator entrypoint (main.go)
+-- internal/
|   +-- controller/            # Reconciler implementations
|   +-- credential/            # JWT parsing, expiry calculation
|   +-- credentialstore/       # CredentialStore interface + backends
|   +-- oid4vci/               # OID4VCI protocol client library
+-- config/
|   +-- crd/                   # Generated CRD manifests
|   +-- rbac/                  # Generated RBAC manifests
|   +-- manager/               # Deployment manifests
|   +-- samples/               # Example Custom Resource manifests
+-- charts/vc-operator/        # Helm chart
+-- test/integration/          # Integration tests
+-- docs/                      # Architecture documentation
+-- Dockerfile
+-- Makefile
```

## Makefile Targets

| Target | Description |
|--------|-------------|
| `make generate` | Run code generators (DeepCopy, object interfaces). |
| `make manifests` | Generate CRD and RBAC manifests from kubebuilder markers. |
| `make build` | Build the operator binary. |
| `make test` | Run unit tests with envtest. |
| `make test-integration` | Run integration tests (build tag: `integration`). |
| `make lint` | Run golangci-lint. |
| `make lint-fix` | Run golangci-lint with auto-fix. |
| `make fmt` | Format Go source code. |
| `make vet` | Run `go vet`. |
| `make docker-build` | Build the container image. |
| `make docker-push` | Push the container image. |
| `make install` | Install CRDs into the current cluster. |
| `make uninstall` | Remove CRDs from the cluster. |
| `make deploy` | Deploy the operator to the cluster. |
| `make undeploy` | Remove the operator from the cluster. |
| `make helm-lint` | Lint the Helm chart. |
| `make helm-template` | Render the Helm chart templates. |
| `make helm-install` | Install via Helm. |
| `make helm-uninstall` | Uninstall the Helm release. |

## Code Conventions

### Go Style

- Follow standard Go conventions and the
  [Effective Go](https://go.dev/doc/effective_go) guidelines.
- All exported types, functions, and methods must have GoDoc comments.
- Use named constants for magic values. Define them in a `constants.go` file
  within the relevant package.

### Kubebuilder Markers

CRD types use kubebuilder markers for validation and generation:

```go
// +kubebuilder:validation:Required
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:Pattern=`^https?://.*`
// +kubebuilder:default="generic"
// +kubebuilder:validation:Enum=generic;keycloak
```

After modifying API types, always regenerate:

```bash
make generate    # Regenerate DeepCopy methods
make manifests   # Regenerate CRD/RBAC YAML
```

### Testing

- **Unit tests:** Use Go's standard `testing` package. Place test files next
  to the code they test (`*_test.go`).
- **envtest:** Controller tests use
  [envtest](https://pkg.go.dev/sigs.k8s.io/controller-runtime/pkg/envtest)
  to run a real Kubernetes API server locally.
- **Integration tests:** Located in `test/integration/`, gated behind the
  `integration` build tag. Use a mock OID4VCI issuer and envtest.
- **Table-driven tests:** Use parameterized (table-driven) tests where
  multiple scenarios share the same test logic.
- **Mock HTTP servers:** Use `net/http/httptest` for mocking external HTTP
  endpoints (OID4VCI metadata, token, credential endpoints).

### Error Handling

- Distinguish between **transient** errors (network timeouts, 5xx responses)
  and **permanent** errors (401, invalid configuration).
- Transient errors trigger exponential backoff retries.
- Permanent errors set an `Error` condition with a descriptive message and
  requeue at a fixed interval.
- Always wrap errors with context: `fmt.Errorf("failed to fetch metadata: %w", err)`.

### Status Conditions

Follow Kubernetes API conventions for status conditions:

- Use standard condition types: `Ready`, `CredentialIssued`,
  `RenewalScheduled`, `Error`.
- Set `ObservedGeneration` to track which spec version the status reflects.
- Use descriptive `Reason` constants (e.g., `MetadataDiscovered`,
  `TokenRequestFailed`).

## Adding a New Storage Backend

The `CredentialStore` interface (`internal/credentialstore/store.go`) abstracts
credential storage. To add a new backend (e.g., HashiCorp Vault):

1. Create a new package: `internal/credentialstore/vault/`.
2. Implement the `CredentialStore` interface:
   ```go
   type VaultStore struct {
       // Vault client, configuration, etc.
   }

   func (s *VaultStore) Store(ctx context.Context, ref credentialstore.TargetRef, data *credentialstore.CredentialData) error { ... }
   func (s *VaultStore) Retrieve(ctx context.Context, ref credentialstore.TargetRef) (*credentialstore.CredentialData, error) { ... }
   func (s *VaultStore) Delete(ctx context.Context, ref credentialstore.TargetRef) error { ... }
   ```
3. Add a new `StorageType` enum value in `api/v1alpha1/verifiablecredentialrequest_types.go`.
4. Wire it up in `cmd/main.go` based on configuration.
5. Write comprehensive tests.

## Submitting Changes

1. Fork the repository and create a feature branch.
2. Make your changes following the conventions above.
3. Ensure all tests pass: `make test && make lint`.
4. Regenerate manifests if API types changed: `make generate && make manifests`.
5. Submit a pull request with a clear description of the changes.

## License

By contributing, you agree that your contributions will be licensed under the
Apache License 2.0.
