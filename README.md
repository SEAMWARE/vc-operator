# vc-operator

A Kubernetes operator that manages Verifiable Credentials (VCs). It obtains credentials
via [OID4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
(OpenID for Verifiable Credential Issuance), stores them as Kubernetes Secrets,
and automatically renews them before expiry.

## Architecture

```
                          +-----------------------+
                          |   Kubernetes Cluster  |
                          |                       |
 +------------------+     |  +----------------+   |     +-------------------+
 | Cluster Admin    |---->|  | vc-operator    |   |     | OID4VCI Issuer    |
 | (kubectl/Helm)   |     |  | (controller)   |---|---->| (e.g., Keycloak)  |
 +------------------+     |  +-------+--------+   |     +-------------------+
                          |          |             |
                          |          | creates/    |
                          |          | updates     |
                          |          v             |
                          |  +----------------+   |     +-------------------+
                          |  | Secrets        |<--|---->| Service Pods      |
                          |  | (credentials)  |   |     | (consume creds)   |
                          |  +----------------+   |     +-------------------+
                          +-----------------------+
```

**How it works:**

1. A cluster admin creates a `CredentialIssuer` resource pointing to an OID4VCI
   issuer (e.g., Keycloak) and a `VerifiableCredentialRequest` specifying the
   credential type needed.
2. The operator discovers the issuer's OID4VCI metadata, authenticates using
   client credentials from a referenced Secret, and obtains a Verifiable
   Credential.
3. The credential is stored in a Kubernetes Secret (or another pluggable backend).
4. The operator monitors credential expiry and automatically renews credentials
   before they expire, ensuring uninterrupted service operation.

## Features

- **OID4VCI Protocol Support** -- Full OpenID for Verifiable Credential Issuance
  flow including metadata discovery, token acquisition, and credential issuance.
- **Automatic Renewal** -- Credentials are renewed before expiry based on
  configurable `renewBefore` duration.
- **Pluggable Storage** -- Credentials are stored via a `CredentialStore`
  interface. Kubernetes Secrets is the default backend; alternative backends
  (e.g., HashiCorp Vault) can be added.
- **Credential Rotation Safety** -- Previous credential is retained alongside the
  new one during rotation, giving consuming services a grace period.
- **Self-Healing Secrets** -- The operator watches the credential Secrets it
  owns. If one is deleted or emptied out-of-band, a replacement credential is
  requested from the issuer and the Secret is re-created immediately, without
  waiting for the scheduled renewal.
- **Prometheus Metrics** -- Built-in metrics for credentials issued, renewed,
  errors, and time-to-expiry.
- **Holder Identity Binding** -- Optionally bind credentials to a specific holder
  identity via proof-of-possession JWTs. Supports both JWK-based and DID-based
  binding.
- **Keycloak Support** -- First-class support for Keycloak as an OID4VCI issuer.
- **IdentityHub Publication** -- Optionally push every issued and renewed
  credential into the credential store of an EDC IdentityHub, so its copy never
  falls behind the one in the Secret. A publication failure is retried on its
  own, without going back to the issuer for a new credential.

## Quick Start

### Prerequisites

- Go 1.22+ (for building from source)
- Docker 17.03+
- kubectl v1.26+
- Access to a Kubernetes v1.26+ cluster
- An OID4VCI-compatible credential issuer (e.g., Keycloak with VC support)

### Install with Helm

```bash
# Add the Helm chart (or install from local source)
helm install vc-operator ./charts/vc-operator \
  --namespace vc-operator-system \
  --create-namespace
```

### Install with Kustomize

```bash
# Install CRDs
make install

# Deploy the operator
make deploy IMG=ghcr.io/wistefan/vc-operator:latest
```

### Create Your First Credential

**1. Create an authentication Secret** with the client credentials for your
OID4VCI issuer:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: keycloak-vc-credentials
type: Opaque
stringData:
  client_id: "my-vc-client"
  client_secret: "my-client-secret"
```

**2. Create a CredentialIssuer** pointing to your OID4VCI issuer:

```yaml
apiVersion: vc.vc-operator.io/v1alpha1
kind: CredentialIssuer
metadata:
  name: my-keycloak-issuer
spec:
  issuerURL: "https://keycloak.example.com/realms/vc-issuer"
  issuerType: keycloak
  authSecretRef:
    name: keycloak-vc-credentials
```

**3. Create a VerifiableCredentialRequest** to obtain a credential:

```yaml
apiVersion: vc.vc-operator.io/v1alpha1
kind: VerifiableCredentialRequest
metadata:
  name: my-service-credential
spec:
  issuerRef:
    name: my-keycloak-issuer
  credentialType: "VerifiableCredential"
  format: jwt_vc_json
  targetSecretRef:
    name: my-service-vc
    key: credential
  renewBefore: 10m
```

**4. Verify** the credential was obtained:

```bash
# Check the VerifiableCredentialRequest status
kubectl get verifiablecredentialrequests
# NAME                    ISSUER               CREDENTIAL TYPE        FORMAT        READY   EXPIRY   RENEWALS   AGE
# my-service-credential   my-keycloak-issuer   VerifiableCredential   jwt_vc_json   True    ...      0          1m

# Check the generated Secret
kubectl get secret my-service-vc -o jsonpath='{.data.credential}' | base64 -d
```

### Holder Identity Binding (Optional)

By default, credentials are issued without being bound to a specific holder. To
bind a credential to a holder identity, provide a holder key and optionally a DID.

**1. Generate an ECDSA P-256 key pair:**

```bash
openssl ecparam -genkey -name prime256v1 -noout -out holder-key.pem
```

**2. Create a Secret with the holder key:**

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-holder-key
type: Opaque
data:
  key.pem: <base64-encoded contents of holder-key.pem>
```

**3. Reference the key in the VerifiableCredentialRequest:**

```yaml
apiVersion: vc.vc-operator.io/v1alpha1
kind: VerifiableCredentialRequest
metadata:
  name: my-service-credential
spec:
  issuerRef:
    name: my-keycloak-issuer
  credentialType: "VerifiableCredential"
  format: jwt_vc_json
  targetSecretRef:
    name: my-service-vc
    key: credential
  # Bind to the holder's key (JWK binding)
  holderKeyRef:
    name: my-holder-key
  # Optional: use a DID instead of raw JWK in the proof
  # holderDID: "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169"
```

When `holderKeyRef` is set, the operator signs a proof-of-possession JWT with the
holder's private key and includes it in the credential request. The issuer then
binds the issued credential to that key.

If `holderDID` is also set, the proof JWT uses a `kid` header with the DID URL
instead of embedding the full JWK public key. This enables DID-based holder
binding. The DID must resolve to the public key corresponding to the private key
in the referenced Secret.

## CRD Reference

### CredentialIssuer

Configures an OID4VCI credential issuer endpoint. Short name: `ciss` (e.g. `kubectl get ciss`).

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `spec.issuerURL` | `string` | Yes | -- | Base URL of the OID4VCI issuer. Metadata is discovered at `{issuerURL}/.well-known/openid-credential-issuer`. Must match `https?://.*` pattern. |
| `spec.issuerType` | `string` | No | `generic` | Issuer implementation type. Supported values: `generic`, `keycloak`. |
| `spec.authSecretRef.name` | `string` | Yes | -- | Name of a Secret containing authentication credentials (`client_id`/`client_secret` or `pre_authorized_code`). |
| `spec.tokenURL` | `string` | No | -- | Override the token endpoint discovered from issuer metadata. Must match `https?://.*` pattern. |

**Status fields:**

| Field | Description |
|-------|-------------|
| `status.credentialEndpoint` | Discovered credential issuance endpoint. |
| `status.tokenEndpoint` | Discovered or overridden token endpoint. |
| `status.supportedCredentialTypes` | List of credential types the issuer supports. |
| `status.lastMetadataFetchTime` | Timestamp of the last successful metadata fetch. |
| `status.conditions` | Standard Kubernetes conditions (`Ready`). |

### VerifiableCredentialRequest

Declares a credential that a service needs. The operator obtains and renews it
automatically. Short name: `vcr` (e.g. `kubectl get vcr`).

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `spec.issuerRef.name` | `string` | Yes | -- | Name of a `CredentialIssuer` in the same namespace. |
| `spec.credentialType` | `string` | Yes | -- | Credential type identifier (as advertised in the issuer's `credential_configurations_supported`). |
| `spec.format` | `string` | No | `jwt_vc_json` | Credential format. Supported: `jwt_vc_json`, `ldp_vc`, `jwt_vc`, `vc+sd-jwt`. |
| `spec.storageType` | `string` | No | `kubernetes` | Storage backend for the credential. Currently only `kubernetes` is supported. |
| `spec.targetSecretRef.name` | `string` | Yes | -- | Name of the Kubernetes Secret where the credential is stored. |
| `spec.targetSecretRef.key` | `string` | No | `credential` | Key within the Secret data map for the credential value. |
| `spec.renewBefore` | `duration` | No | `5m` | How long before credential expiry to attempt renewal (e.g., `5m`, `1h`). |
| `spec.additionalClaims` | `map[string]string` | No | -- | Extra claims to include in the credential request (issuer-specific). |
| `spec.holderKeyRef.name` | `string` | No | -- | Name of a Secret containing the holder's ECDSA P-256 private key in PEM format (data key `key.pem` or `tls.key`). When set, the operator signs a proof-of-possession JWT with this key, binding the credential to the holder. |
| `spec.holderDID` | `string` | No | -- | DID URL to use as the `kid` header in the proof JWT instead of embedding the full JWK. Requires `holderKeyRef` to be set. |
| `spec.identityHub.url` | `string` | Yes* | -- | Base URL of the IdentityHub Identity API including the version segment, e.g. `http://identityhub-service:8082/api/identity/v1alpha`. |
| `spec.identityHub.participantId` | `string` | Yes* | -- | Participant context the credential belongs to, i.e. the participant's DID. Base64url-encoded into the request path by the operator. |
| `spec.identityHub.apiKeyRef` | `object` | Yes* | -- | `name`/`key` of a Secret holding the IdentityHub api key, already in the composed `base64(participantContextId).secret` form. |
| `spec.identityHub.credentialId` | `string` | No | request name | Id the credential is stored under in the IdentityHub. Must be stable so a renewal replaces the stored copy. |

\* Required only when `spec.identityHub` is present, which is optional.

**Status fields:**

| Field | Description |
|-------|-------------|
| `status.credentialExpiryTime` | When the current credential expires. |
| `status.lastIssuanceTime` | When the credential was last issued. |
| `status.lastRenewalTime` | When the credential was last renewed. |
| `status.nextRenewalTime` | When the next renewal attempt is scheduled. |
| `status.renewalCount` | Total number of successful renewals. |
| `status.credentialFormat` | Format of the stored credential. |
| `status.conditions` | Standard Kubernetes conditions (`Ready`, `CredentialIssued`, `RenewalScheduled`, `Error`, and `IdentityHubPublished` when `spec.identityHub` is set). |

`IdentityHubPublished=False` means the credential in the Secret is valid but the
IdentityHub copy is behind it, so DCP exchanges may still present the previous
credential. The operator retries only the publication in that state: it does not
request a new credential from the issuer, and the stored copy and its rotation
buffer are left untouched.

## Stored Secret Format

When a credential is obtained, the operator creates a Kubernetes Secret with the
following structure:

| Key | Description |
|-----|-------------|
| `credential` (or custom key) | The Verifiable Credential (e.g., JWT string). |
| `format` | The credential format (e.g., `jwt_vc_json`). |
| `expiryTimestamp` | RFC 3339 timestamp of credential expiry. |
| `issuedAtTimestamp` | RFC 3339 timestamp of credential issuance. |
| `previousCredential` | The previous credential (retained during rotation). |

**Labels applied:**
- `app.kubernetes.io/managed-by: vc-operator`
- `app.kubernetes.io/component: credential`

**Annotations applied:**
- `vc-operator.io/credential-type: <credential-type>`
- `vc-operator.io/source-cr: <namespace>/<cr-name>`

**Self-healing:** The Secret is owned by its `VerifiableCredentialRequest`, and
the operator watches it. Deleting the Secret -- or emptying the credential key --
triggers an immediate reconciliation instead of waiting for
`status.nextRenewalTime`. Two consequences are worth knowing:

- The operator keeps no copy of the credential anywhere, so restoring the Secret
  costs a **full round-trip to the issuer**, exactly like a renewal.
- The restored Secret has **no `previousCredential`**: the rotation buffer was
  stored inside the deleted Secret and is lost with it, so consuming services
  still holding the old credential get no grace period.

A restore is recorded as a renewal: it increments `status.renewalCount`, sets
`status.lastRenewalTime` and increments `vc_operator_credentials_renewed_total`.
The distinguishing signal is the `StoredCredentialMissing` Warning event emitted
when the loss is detected.

## Configuration Reference

### Operator Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--metrics-bind-address` | `0` (disabled) | Bind address for the metrics endpoint. Set to `:8443` for HTTPS or `:8080` for HTTP. |
| `--health-probe-bind-address` | `:8081` | Bind address for the health probe endpoint (`/healthz`, `/readyz`). |
| `--leader-elect` | `false` | Enable leader election for high availability. |
| `--metrics-secure` | `true` | Serve metrics over HTTPS. |
| `--enable-http2` | `false` | Enable HTTP/2 for metrics and webhook servers. |
| `--metrics-cert-path` | -- | Directory containing TLS certificate for the metrics server. |
| `--webhook-cert-path` | -- | Directory containing TLS certificate for webhooks. |

### Helm Chart Values

See [`charts/vc-operator/values.yaml`](charts/vc-operator/values.yaml) for the
full list of configurable values. Key settings:

| Value | Default | Description |
|-------|---------|-------------|
| `replicaCount` | `1` | Number of operator replicas. |
| `image.repository` | `ghcr.io/wistefan/vc-operator` | Container image repository. |
| `image.tag` | Chart `appVersion` | Container image tag. |
| `leaderElection.enabled` | `true` | Enable leader election. |
| `metrics.bindAddress` | `:8443` | Metrics endpoint bind address. |
| `metrics.secure` | `true` | Serve metrics over HTTPS. |
| `resources.limits.cpu` | `500m` | CPU limit. |
| `resources.limits.memory` | `128Mi` | Memory limit. |
| `crds.install` | `true` | Install CRDs with the Helm chart. |

### Prometheus Metrics

The operator exposes the following Prometheus metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `vc_operator_credentials_issued_total` | Counter | Total number of credentials successfully issued. |
| `vc_operator_credentials_renewed_total` | Counter | Total number of credentials successfully renewed. |
| `vc_operator_credential_errors_total` | Counter | Total number of credential issuance/renewal errors. |
| `vc_operator_credential_expiry_seconds` | Gauge | Time in seconds until the credential expires. |

## Troubleshooting

### CredentialIssuer stays in `Ready=False`

**Symptom:** The `CredentialIssuer` resource does not reach `Ready=True`.

**Check issuer connectivity:**
```bash
kubectl describe credentialissuer <name>
```

Look at the `Conditions` section for the reason:

| Reason | Cause | Resolution |
|--------|-------|------------|
| `MetadataFetchFailed` | Cannot reach the issuer URL or metadata endpoint returned an error. | Verify the `issuerURL` is correct and accessible from the cluster. Check network policies and DNS. |
| `AuthSecretNotFound` | The referenced authentication Secret does not exist. | Create the Secret with the correct name in the same namespace. |
| `AuthSecretInvalid` | The Secret is missing required keys. | Ensure the Secret has `client_id` and `client_secret` (or `pre_authorized_code`) keys. |

### VerifiableCredentialRequest stays in `Ready=False`

**Symptom:** The credential request does not succeed.

```bash
kubectl describe verifiablecredentialrequest <name>
```

| Reason | Cause | Resolution |
|--------|-------|------------|
| `IssuerNotFound` | The referenced `CredentialIssuer` does not exist. | Create the `CredentialIssuer` resource first, or fix the `issuerRef.name`. |
| `IssuerNotReady` | The referenced `CredentialIssuer` is not yet `Ready`. | Wait for the issuer to become ready, or check its status for errors. |
| `TokenRequestFailed` | Failed to obtain an access token from the issuer. | Verify client credentials are correct. Check issuer logs. |
| `CredentialRequestFailed` | The credential issuance request was rejected. | Verify the `credentialType` is supported by the issuer. Check the issuer's `credential_configurations_supported`. |
| `StorageFailed` | Failed to create or update the target Secret. | Check RBAC permissions. Ensure no conflicting Secret exists with different ownership. |
| `HolderKeyInvalid` | The `holderKeyRef` Secret is missing, contains invalid key data, or `holderDID` is set without `holderKeyRef`. | Verify the holder key Secret exists and contains a valid ECDSA P-256 private key under the `key.pem` or `tls.key` data key. If using `holderDID`, ensure `holderKeyRef` is also set. |

### Credential not renewing

**Symptom:** The credential expires without being renewed.

1. Check `status.nextRenewalTime` on the `VerifiableCredentialRequest`:
   ```bash
   kubectl get vcr <name> -o jsonpath='{.status.nextRenewalTime}'
   ```
2. Check operator logs for renewal errors:
   ```bash
   kubectl logs -n vc-operator-system deployment/vc-operator-controller-manager
   ```
3. Ensure the `renewBefore` duration is less than the credential's lifetime.

### Deleted credential Secret keeps coming back

**Symptom:** You delete a credential Secret and the operator re-creates it within
seconds.

This is intentional -- see [Stored Secret Format](#stored-secret-format). The
Secret is declared by a `VerifiableCredentialRequest`, so as long as that CR
exists the operator keeps its Secret present.

1. Confirm the operator is the cause:
   ```bash
   kubectl get events -n <namespace> --field-selector reason=StoredCredentialMissing
   ```
2. To remove the Secret for good, delete the CR that declares it. The Secret is
   garbage-collected via its owner reference:
   ```bash
   kubectl delete vcr <name> -n <namespace>
   ```

### View operator events

```bash
kubectl get events --field-selector involvedObject.kind=CredentialIssuer
kubectl get events --field-selector involvedObject.kind=VerifiableCredentialRequest
```

## Examples

Complete example configurations are available in
[`config/samples/keycloak-example/`](config/samples/keycloak-example/). See the
[README](config/samples/keycloak-example/README.md) in that directory for
step-by-step instructions.

Additional examples:
- [Basic sample](config/samples/vc_v1alpha1_credentialissuer.yaml) -- Minimal
  `CredentialIssuer` and `VerifiableCredentialRequest`.
- [Holder binding](config/samples/vc_v1alpha1_verifiablecredentialrequest_holder_binding.yaml)
  -- Request with holder identity binding via key and DID.
- [Custom renewal interval](config/samples/keycloak-example/vcrequest-custom-renewal.yaml)
  -- Request with a 1-hour renewal buffer.
- [Additional claims](config/samples/keycloak-example/vcrequest-additional-claims.yaml)
  -- Request with extra issuer-specific claims.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for build instructions, testing, and
contribution guidelines.

See [docs/architecture.md](docs/architecture.md) for architecture decisions and
design rationale.

## License

Copyright 2026 Seamless Middleware Technologies S.L and/or its affiliates
and other contributors as indicated by the @author tags.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
