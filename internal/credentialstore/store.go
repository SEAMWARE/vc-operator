/*
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
*/

// Package credentialstore defines the CredentialStore interface that abstracts
// storage operations for obtained Verifiable Credentials. The default
// implementation uses Kubernetes Secrets (see the kubernetes sub-package).
// Alternative backends (e.g., HashiCorp Vault, AWS Secrets Manager) can be
// added by implementing this interface.
package credentialstore

import (
	"context"
	"errors"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// ErrNotFound is returned by Retrieve when no credential exists at the given
// TargetRef, or when the stored object exists but carries no credential
// payload. Backends must wrap this sentinel so that callers can distinguish a
// genuinely absent credential from a transient backend failure.
var ErrNotFound = errors.New("credential not found in store")

// CredentialStore abstracts the storage backend for obtained credentials.
// The default implementation uses Kubernetes Secrets. Alternative backends
// (e.g., HashiCorp Vault, AWS Secrets Manager) can be added by implementing
// this interface.
type CredentialStore interface {
	// Store persists a credential to the storage backend. If a credential
	// already exists at the target reference, it is updated. The previous
	// credential (if any) is preserved in the CredentialData for rotation.
	Store(ctx context.Context, ref TargetRef, data *CredentialData) error

	// Retrieve loads a previously stored credential from the storage
	// backend. Implementations must return an error wrapping ErrNotFound
	// when no credential is stored at the given reference, or when the
	// stored object exists but carries no credential payload. Any other
	// error indicates a transient backend failure.
	Retrieve(ctx context.Context, ref TargetRef) (*CredentialData, error)

	// Delete removes a stored credential from the storage backend.
	// Returns nil if the credential does not exist (idempotent).
	Delete(ctx context.Context, ref TargetRef) error
}

// TargetRef identifies a credential storage location within the backend.
// For Kubernetes Secrets, this maps to a namespace/name pair with optional
// owner reference information for garbage collection.
type TargetRef struct {
	// Namespace is the Kubernetes namespace of the target resource.
	Namespace string

	// Name is the name of the target resource (e.g., the Secret name).
	Name string

	// Key is the data key within the target resource under which the
	// credential is stored.
	Key string

	// OwnerGVK is the GroupVersionKind of the owning resource, used to
	// set owner references for garbage collection.
	OwnerGVK metav1.GroupVersionKind

	// OwnerUID is the UID of the owning custom resource, used to set
	// owner references for garbage collection.
	OwnerUID types.UID

	// OwnerName is the name of the owning custom resource, used to set
	// owner references for garbage collection.
	OwnerName string
}

// CredentialData contains the credential payload and expiry metadata
// for storage and lifecycle management. The operator only stores
// information needed for credential renewal scheduling; it does not
// interpret identity claims or VC-specific content.
type CredentialData struct {
	// Credential is the raw credential bytes (e.g., the compact JWT string).
	Credential []byte

	// Format is the credential format identifier (e.g., "jwt_vc_json").
	Format string

	// ExpiryTime is the credential's expiry time. Zero value means the
	// credential does not have an explicit expiry.
	ExpiryTime time.Time

	// IssuedAt is the time the credential was issued.
	IssuedAt time.Time

	// PreviousCredential holds the previous credential for rotation buffer
	// purposes. This allows consuming services a grace period when
	// credentials are renewed. Nil if no previous credential exists.
	PreviousCredential []byte
}
