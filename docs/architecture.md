# Architecture

This document describes the architecture of the vc-operator and records key
design decisions with their rationale.

## Overview

The vc-operator is a Kubernetes operator that automates the lifecycle of
Verifiable Credentials (VCs) for services in FIWARE-ecosystem deployments. It
follows the [operator pattern](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/)
to declare desired credential state via Custom Resources and reconcile that state
continuously.

## Component Architecture

```
+------------------------------------------------------+
|                    Kubernetes API                     |
+------+----------+----------+----------+--------------+
       |          |          |          |
       v          v          v          v
  +---------+ +--------+ +--------+ +--------+
  | Cred.   | | VC     | | Auth   | | Target |
  | Issuer  | | Request| | Secret | | Secret |
  | (CR)    | | (CR)   | | (data) | | (cred) |
  +---------+ +--------+ +--------+ +--------+
       |          |          ^          ^
       v          v          |          |
  +---------+ +----------+  |          |
  | Cred.   | | VCReq.   |--+          |
  | Issuer  | | Reconciler|---> CredentialStore
  | Reconc. | +-----+-----+      Interface
  +---------+       |                |
       |            v                v
       |      +----------+    +-----------+
       |      | OID4VCI  |    | Secret    |
       +----->| Client   |    | Store     |
              +-----+----+    +-----------+
                    |
                    v
              +----------+
              | External |
              | OID4VCI  |
              | Issuer   |
              +----------+
```

### Custom Resources

- **CredentialIssuer** -- Represents an OID4VCI credential issuer endpoint (e.g.,
  a Keycloak realm). The operator discovers and caches the issuer's OID4VCI
  metadata. Multiple `VerifiableCredentialRequest` resources can reference the
  same issuer.

- **VerifiableCredentialRequest** -- Declares that a service needs a specific
  Verifiable Credential. References a `CredentialIssuer` and specifies the
  credential type, format, storage target, and renewal policy.

### Controllers

- **CredentialIssuer Reconciler** -- Validates issuer connectivity, fetches
  OID4VCI metadata (credential endpoint, token endpoint, supported types), and
  periodically refreshes metadata (every 30 minutes). Sets `Ready` condition on
  the CR.

- **VerifiableCredentialRequest Reconciler** -- Orchestrates the full credential
  lifecycle: token acquisition, credential issuance, storage, and renewal. Uses
  the OID4VCI client library and the `CredentialStore` interface. Implements
  exponential backoff for transient errors and distinguishes between retriable
  and permanent failures. Also watches the credential Secrets it owns, so one
  deleted or emptied out-of-band is re-issued immediately (see ADR-8).

### Internal Libraries

- **OID4VCI Client** (`internal/oid4vci/`) -- Standalone protocol client that
  implements the OpenID for Verifiable Credential Issuance specification:
  metadata discovery, OAuth 2.0 token acquisition (client credentials and
  pre-authorized code grants), and credential issuance requests with
  proof-of-possession JWTs.

- **Credential Parsing** (`internal/credential/`) -- JWT VC parsing, claim
  extraction, and expiry calculation. Parses JWT compact serialization without
  full signature verification (the operator trusts the issuer).

- **Credential Store** (`internal/credentialstore/`) -- Pluggable storage
  interface with a Kubernetes Secrets default backend.

## Architecture Decision Records

### ADR-1: Go with Kubebuilder

**Status:** Accepted

**Context:** We need to build a Kubernetes operator that watches Custom Resources
and reconciles state. The FIWARE ecosystem has operators in both Go and Java.

**Decision:** Use Go with the Kubebuilder framework (controller-runtime).

**Rationale:**
- Kubebuilder is the de facto standard for building Kubernetes operators in Go,
  maintained by the Kubernetes SIG.
- controller-runtime provides battle-tested reconciliation patterns, leader
  election, metrics, health probes, and envtest for testing.
- Go produces small, statically-linked binaries ideal for container images.
- The operator SDK ecosystem (code generators, CRD markers, RBAC markers) reduces
  boilerplate significantly.
- Most Kubernetes operators in the ecosystem are written in Go, making it easier
  for contributors familiar with Kubernetes internals.

**Alternatives considered:**
- **Java with Quarkus Operator SDK** -- Viable, but heavier runtime footprint and
  less mature CRD generation tooling.
- **Rust with kube-rs** -- Excellent performance, but smaller ecosystem and steeper
  learning curve for Kubernetes operator patterns.

---

### ADR-2: CredentialStore Interface for Pluggable Storage

**Status:** Accepted

**Context:** Credentials must be stored securely. Kubernetes Secrets are the
simplest option, but enterprise deployments often require external secret
management (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault).

**Decision:** Define a `CredentialStore` interface and inject it into the
controller via dependency injection. The default implementation uses Kubernetes
Secrets.

**Rationale:**
- The interface abstracts storage operations (`Store`, `Retrieve`, `Delete`)
  behind a clean contract, allowing the controller logic to remain
  storage-agnostic.
- New backends can be added by implementing the interface without modifying
  controller code.
- The controller receives the store via its constructor, making it easy to swap
  implementations and inject mocks for testing.
- Kubernetes Secrets is a sensible default that works everywhere without external
  dependencies.

**Interface:**
```go
type CredentialStore interface {
    Store(ctx context.Context, ref TargetRef, data *CredentialData) error
    Retrieve(ctx context.Context, ref TargetRef) (*CredentialData, error)
    Delete(ctx context.Context, ref TargetRef) error
}
```

**Trade-offs:**
- Adds a level of indirection compared to direct Secret manipulation.
- Each new backend requires implementation and testing effort.
- The `TargetRef` struct must be generic enough for all backends while specific
  enough for Kubernetes owner references.

---

### ADR-3: OID4VCI Protocol Flow Selection

**Status:** Accepted

**Context:** The OID4VCI specification defines multiple flows for credential
issuance. We need to select which flows to support for service-to-service
credential acquisition.

**Decision:** Support the `client_credentials` grant as the primary flow and the
`pre-authorized_code` grant as a secondary flow.

**Rationale:**
- **Client credentials grant** is the standard OAuth 2.0 flow for
  service-to-service authentication. It requires no user interaction, making it
  ideal for automated operator workflows.
- **Pre-authorized code grant** supports scenarios where an administrator
  pre-authorizes credential issuance and provides a one-time code. This is useful
  for initial bootstrapping or constrained environments.
- The **authorization code flow** (interactive, browser-based) is not supported
  because the operator runs as a background service without user interaction
  capability.

**Implementation:**
- The grant type is determined by the contents of the auth Secret:
  - If `client_id` and `client_secret` are present: use client credentials grant.
  - If `pre_authorized_code` is present: use pre-authorized code grant.
- The OID4VCI client supports proof-of-possession JWTs signed with a
  holder-provided ECDSA P-256 key pair to bind the credential to a specific
  holder identity. When no holder key is configured, no proof is included.

---

### ADR-4: Two-CRD Design (CredentialIssuer + VerifiableCredentialRequest)

**Status:** Accepted

**Context:** We need to model the relationship between credential issuers and
credential requests. A single CRD could combine both, or they can be separated.

**Decision:** Use two separate CRDs: `CredentialIssuer` for issuer configuration
and `VerifiableCredentialRequest` for individual credential requests.

**Rationale:**
- **Separation of concerns:** Issuer configuration (URL, auth credentials) is
  distinct from credential specification (type, format, storage).
- **Reusability:** Multiple credential requests can reference the same issuer,
  avoiding configuration duplication.
- **Independent lifecycle:** Issuer connectivity can be validated independently
  of credential requests. An issuer can be configured and verified before any
  credentials are requested.
- **RBAC granularity:** Different teams can have permissions on issuers vs.
  credential requests.
- **Follows Kubernetes patterns:** Similar to how `Ingress` references
  `IngressClass`, or `Certificate` references `ClusterIssuer` in cert-manager.

**Trade-offs:**
- Two CRDs mean more resources to manage.
- Cross-resource references require lookup during reconciliation.

---

### ADR-5: Credential Renewal Strategy

**Status:** Accepted

**Context:** Verifiable Credentials have limited lifetimes. The operator must
renew them before expiry to prevent service disruption.

**Decision:** Use time-based proactive renewal with a configurable `renewBefore`
buffer. Store the previous credential alongside the new one for rotation safety.

**Rationale:**
- **Proactive renewal:** The operator calculates `nextRenewalTime = expiryTime -
  renewBefore` and requeues the reconciliation at that time. This ensures renewal
  happens before expiry, even if there are transient failures (multiple retry
  attempts before the credential actually expires).
- **Configurable buffer:** Different deployments have different requirements. A
  5-minute default works for most cases, but long-lived credentials in
  unreliable networks may need a larger buffer.
- **Rotation safety:** The previous credential is stored alongside the new one in
  the `CredentialData` (one-deep rotation buffer). This gives consuming services
  a grace period to pick up the new credential without immediately invalidating
  the old one.
- **Exponential backoff:** Transient failures during renewal are retried with
  exponential backoff, preventing thundering herd effects if the issuer is
  temporarily overloaded.

**Implementation details:**
- `renewBefore` defaults to 5 minutes.
- Minimum renewal interval is 30 seconds (to prevent tight retry loops).
- Maximum credential lifetime is 365 days.
- Credentials without an explicit expiry are treated as having a 24-hour default
  TTL.

---

### ADR-6: JWT Parsing Without Signature Verification

**Status:** Accepted

**Context:** The operator receives JWT Verifiable Credentials from the issuer and
needs to extract claims (expiry, issued-at) for lifecycle management.

**Decision:** Parse JWT claims by decoding the payload segment without performing
signature verification.

**Rationale:**
- The operator acts as a **holder**, not a **verifier**. It trusts the issuer
  because it just requested the credential from an authenticated endpoint.
- Signature verification would require the operator to fetch and manage the
  issuer's public keys (JWK sets), adding complexity and external dependencies.
- The operator only needs the `exp` and `iat` claims for renewal scheduling.
- Consuming services (verifiers) are responsible for full signature verification
  when they use the credential.

**Trade-offs:**
- A compromised TLS connection could theoretically deliver a tampered JWT. This
  risk is mitigated by using HTTPS for all issuer communication.
- If signature verification is needed in the future, it can be added as an
  optional validation step without changing the parsing logic.

### ADR-7: Holder Identity Binding via Proof-of-Possession

**Status:** Accepted

**Context:** Verifiable Credentials can be bound to a specific holder identity so
that only the holder can present the credential. Without holder binding, any party
with access to the credential can present it. The OID4VCI specification supports
holder binding through proof-of-possession JWTs included in the credential
request.

**Decision:** Support optional per-request holder binding via a `holderKeyRef`
field on `VerifiableCredentialRequest`. When set, the operator reads the holder's
ECDSA P-256 private key from the referenced Secret and signs a proof-of-possession
JWT with it. An optional `holderDID` field allows DID-based binding (using `kid`
header) instead of raw JWK binding.

**Rationale:**
- **Per-request, not per-issuer:** Holder binding is on the
  `VerifiableCredentialRequest` because different services may need credentials
  bound to different identities from the same issuer.
- **Key in Secret, not DID resolution:** The operator needs the private key to
  sign the proof JWT. Requiring the key in a Kubernetes Secret is consistent with
  how auth credentials are already managed. The operator does not need a DID
  resolver -- it trusts the user to provide a DID that matches the key.
- **ECDSA P-256 only:** The OID4VCI specification requires ES256 for proof JWTs.
  Supporting additional algorithms is future work.
- **Fully optional and backward-compatible:** Both fields default to nil/empty.
  Omitting them preserves the existing behavior (no proof, no holder binding).
- **Two binding modes:** JWK binding (embed public key in proof header) for
  simple cases, and DID binding (reference a DID URL via `kid` header) for
  deployments using Decentralized Identifiers.

**Trade-offs:**
- The holder's private key must be stored in a Kubernetes Secret, which requires
  appropriate RBAC and Secret management practices.
- The operator does not verify that the DID resolves to the correct public key.
  A mismatch will cause the issuer to reject the request at runtime.
- Only ECDSA P-256 keys are supported. Ed25519 (common in `did:key`) and RSA
  keys are not yet supported.

---

### ADR-8: Self-Healing of Credential Secrets

**Status:** Accepted

**Context:** The reconciler's fast path skipped any request whose `Ready`
condition was `True` and whose `status.nextRenewalTime` was still in the future.
That gate consulted only the status, never the storage backend, and the
controller watched nothing but the `VerifiableCredentialRequest` itself. A
credential Secret deleted out-of-band therefore stayed missing until the next
scheduled renewal -- typically `exp - renewBefore`, so hours or days -- leaving
the consuming service without a credential for that entire window.

**Decision:** Watch the credential Secrets the controller owns, and make the
renewal gate consult the `CredentialStore` before skipping. `Retrieve` now
reports an absent credential as `credentialstore.ErrNotFound`, which the
reconciler treats as "re-issue now" regardless of the renewal schedule.

**Rationale:**
- **`Owns` rather than `Watches`:** Credential Secrets already carried an owner
  reference with `Controller: true`, so `Owns` maps Secret events back to the
  owning request exactly, with no field index and no RBAC change (`watch` on
  Secrets was already granted). The Secret informer was already running, because
  both controllers read auth and holder-key Secrets through the cached client,
  so the watch adds no cache cost.
- **Filtering the operator's own writes:** `storeCredential` runs before the
  status update, so an unfiltered watch would enqueue a redundant reconciliation
  after every issuance, plus one per managed Secret on every informer resync. The
  predicate admits only deletions and updates that removed or emptied a data key.
- **A sentinel, not "any error means missing":** A successful reconciliation
  resets the workqueue rate limiter, so treating every transient backend failure
  as a missing credential would let a flaky backend drive an unthrottled
  re-issuance storm against the issuer. Only `ErrNotFound` triggers re-issuance;
  any other error is assumed to mean the credential is present.
- **Drift comes for free:** Mapping the existing "Secret has no credential key"
  branch onto the same sentinel means an emptied Secret self-heals exactly like a
  deleted one, without a second lookup.
- **The gate stays pure:** The lookup happens in `Reconcile` and its outcome is
  passed into `skipIfNotDueForRenewal` as a boolean, keeping that helper a pure
  function of status and clock.

**Trade-offs:**
- The operator keeps no copy of the credential, so a restore costs a full
  issuer round-trip. Repeated deletion of a Secret produces one round-trip per
  deletion with no debouncing.
- The restored Secret has no `previousCredential`: the rotation buffer lived in
  the deleted Secret, so consumers holding the old credential get no grace
  period.
- A restore reuses the renewal accounting path, so it increments
  `status.renewalCount` and `vc_operator_credentials_renewed_total`. The
  `StoredCredentialMissing` Warning event is what distinguishes a restore from a
  scheduled renewal.
- Every reconciliation performs one additional cached read of the target Secret.

---

## Data Flow

### Credential Issuance Flow

```
1. User creates CredentialIssuer CR
   |
   v
2. CredentialIssuer Reconciler
   |-- Fetches .well-known/openid-credential-issuer metadata
   |-- Validates auth Secret exists and has required keys
   |-- Updates status with discovered endpoints
   |-- Sets Ready=True condition
   |
3. User creates VerifiableCredentialRequest CR
   |
   v
4. VCRequest Reconciler
   |-- Checks whether the stored credential is still present
   |   (absent => re-issue now, ignoring the renewal schedule)
   |-- Skips if stored, valid and not yet due for renewal
   |-- Looks up referenced CredentialIssuer (must be Ready)
   |-- Reads client credentials from auth Secret
   |-- Calls OID4VCI Client:
   |   |-- POST token endpoint (client_credentials grant)
   |   |-- Resolves holder key from holderKeyRef Secret (if configured)
   |   |-- Generates proof-of-possession JWT with holder key (if configured)
   |   |-- POST credential endpoint (with optional proof-of-possession)
   |   |-- Returns CredentialResponse
   |-- Parses JWT to extract expiry
   |-- Stores credential via CredentialStore interface
   |-- Sets CredentialIssued=True, Ready=True conditions
   |-- Calculates nextRenewalTime = expiry - renewBefore
   |-- Requeues at nextRenewalTime
   |
5. Renewal (triggered by requeue, or by the Secret watch on credential loss)
   |-- Re-executes the full credential acquisition flow
   |-- Updates Secret with new credential (retains previous)
   |-- Increments renewalCount
   |-- Requeues for next renewal
```

### Error Handling Flow

```
Transient errors (network, timeout, 5xx):
  --> Exponential backoff starting at 10 seconds
  --> Retry up to the credential's remaining lifetime

Permanent errors (401, 403, invalid config):
  --> Set Error condition with descriptive message
  --> Requeue at ConfigErrorRequeueInterval (1 minute)
  --> No exponential backoff (config needs manual fix)

Holder key errors (missing Secret, invalid PEM, DID without key):
  --> Set Error condition with HolderKeyInvalid reason
  --> Requeue at ConfigErrorRequeueInterval (1 minute)
  --> Requires user to fix the holder key Secret

Issuer not ready:
  --> Requeue at IssuerNotReadyRequeueInterval (30 seconds)
  --> Will succeed once the issuer becomes Ready
```
