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

// Package kubernetes implements the credentialstore.CredentialStore interface
// using Kubernetes Secrets as the storage backend. Credentials are stored as
// Opaque Secrets with structured data keys, operator-managed labels and
// annotations, and owner references for automatic garbage collection.
package kubernetes

import (
	"context"
	"fmt"
	"maps"
	"strconv"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/SEAMWARE/vc-operator/internal/credentialstore"
)

// Secret data key constants define the keys used in the Kubernetes Secret's
// Data map to store credential information.
const (
	// SecretKeyCredential is the data key for the primary credential.
	SecretKeyCredential = "credential"

	// SecretKeyFormat is the data key for the credential format identifier.
	SecretKeyFormat = "format"

	// SecretKeyExpiryTimestamp is the data key for the credential expiry
	// time stored as a Unix timestamp string.
	SecretKeyExpiryTimestamp = "expiryTimestamp"

	// SecretKeyIssuedAtTimestamp is the data key for the credential
	// issued-at time stored as a Unix timestamp string.
	SecretKeyIssuedAtTimestamp = "issuedAtTimestamp"

	// SecretKeyPreviousCredential is the data key for the previous
	// credential, retained during rotation for a grace period.
	SecretKeyPreviousCredential = "previousCredential"
)

// Label and annotation constants for operator-managed Secrets.
const (
	// LabelManagedBy is the standard Kubernetes label key indicating
	// which tool manages a resource.
	LabelManagedBy = "app.kubernetes.io/managed-by"

	// LabelManagedByValue is the value of the managed-by label applied
	// to Secrets created by the vc-operator.
	LabelManagedByValue = "vc-operator"

	// LabelComponent is a label identifying the component type of the Secret.
	LabelComponent = "app.kubernetes.io/component"

	// LabelComponentValue is the component label value for credential Secrets.
	LabelComponentValue = "credential"

	// AnnotationCredentialType is an annotation recording the credential
	// type that was requested from the issuer.
	AnnotationCredentialType = "vc-operator.io/credential-type"

	// AnnotationSourceCR is an annotation recording the name of the
	// VerifiableCredentialRequest CR that owns this Secret.
	AnnotationSourceCR = "vc-operator.io/source-cr"
)

// SecretStore implements credentialstore.CredentialStore using Kubernetes
// Secrets as the storage backend. It uses the controller-runtime client
// for all Kubernetes API interactions.
type SecretStore struct {
	client client.Client
}

// Compile-time interface compliance check.
var _ credentialstore.CredentialStore = (*SecretStore)(nil)

// NewSecretStore creates a new SecretStore backed by the given
// controller-runtime Kubernetes client.
func NewSecretStore(c client.Client) *SecretStore {
	return &SecretStore{client: c}
}

// Store persists a credential as a Kubernetes Secret. If the Secret already
// exists, it is updated in place. The Secret includes operator-managed
// labels, annotations, and owner references for garbage collection.
func (s *SecretStore) Store(ctx context.Context, ref credentialstore.TargetRef, data *credentialstore.CredentialData) error {
	if ref.Name == "" || ref.Namespace == "" {
		return fmt.Errorf("target ref must have both name and namespace")
	}

	secret := buildSecret(ref, data)

	// Try to get existing Secret.
	existing := &corev1.Secret{}
	err := s.client.Get(ctx, types.NamespacedName{
		Namespace: ref.Namespace,
		Name:      ref.Name,
	}, existing)

	if errors.IsNotFound(err) {
		// Create new Secret.
		return s.client.Create(ctx, secret)
	}
	if err != nil {
		return fmt.Errorf("failed to check for existing secret %s/%s: %w", ref.Namespace, ref.Name, err)
	}

	// Update existing Secret: preserve any labels/annotations not managed
	// by us, then overwrite our managed fields.
	existing.Data = secret.Data
	mergeLabels(existing, secret.Labels)
	mergeAnnotations(existing, secret.Annotations)
	existing.OwnerReferences = secret.OwnerReferences

	return s.client.Update(ctx, existing)
}

// Retrieve loads a credential from a Kubernetes Secret. When the Secret does
// not exist, the returned error wraps credentialstore.ErrNotFound so that
// callers can tell an absent credential from a transient API failure.
func (s *SecretStore) Retrieve(ctx context.Context, ref credentialstore.TargetRef) (*credentialstore.CredentialData, error) {
	secret := &corev1.Secret{}
	err := s.client.Get(ctx, types.NamespacedName{
		Namespace: ref.Namespace,
		Name:      ref.Name,
	}, secret)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, fmt.Errorf("secret %s/%s not found: %w",
				ref.Namespace, ref.Name, credentialstore.ErrNotFound)
		}
		return nil, fmt.Errorf("failed to get secret %s/%s: %w", ref.Namespace, ref.Name, err)
	}

	return parseSecretData(secret, ref.Key)
}

// Delete removes a credential Secret. Returns nil if the Secret does not
// exist (idempotent).
func (s *SecretStore) Delete(ctx context.Context, ref credentialstore.TargetRef) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ref.Namespace,
			Name:      ref.Name,
		},
	}

	err := s.client.Delete(ctx, secret)
	if errors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to delete secret %s/%s: %w", ref.Namespace, ref.Name, err)
	}
	return nil
}

// buildSecret constructs a Kubernetes Secret from a TargetRef and
// CredentialData, applying the operator's standard labels, annotations,
// and owner references.
func buildSecret(ref credentialstore.TargetRef, data *credentialstore.CredentialData) *corev1.Secret {
	credKey := ref.Key
	if credKey == "" {
		credKey = SecretKeyCredential
	}

	secretData := map[string][]byte{
		credKey:         data.Credential,
		SecretKeyFormat: []byte(data.Format),
	}

	if !data.ExpiryTime.IsZero() {
		secretData[SecretKeyExpiryTimestamp] = []byte(strconv.FormatInt(data.ExpiryTime.Unix(), 10))
	}

	if !data.IssuedAt.IsZero() {
		secretData[SecretKeyIssuedAtTimestamp] = []byte(strconv.FormatInt(data.IssuedAt.Unix(), 10))
	}

	if len(data.PreviousCredential) > 0 {
		secretData[SecretKeyPreviousCredential] = data.PreviousCredential
	}

	labels := map[string]string{
		LabelManagedBy: LabelManagedByValue,
		LabelComponent: LabelComponentValue,
	}

	annotations := map[string]string{}
	if ref.OwnerName != "" {
		annotations[AnnotationSourceCR] = ref.OwnerName
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        ref.Name,
			Namespace:   ref.Namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Type: corev1.SecretTypeOpaque,
		Data: secretData,
	}

	// Set owner reference if owner information is provided.
	if ref.OwnerUID != "" && ref.OwnerName != "" {
		blockOwnerDeletion := true
		isController := true
		secret.OwnerReferences = []metav1.OwnerReference{
			{
				APIVersion:         ref.OwnerGVK.Group + "/" + ref.OwnerGVK.Version,
				Kind:               ref.OwnerGVK.Kind,
				Name:               ref.OwnerName,
				UID:                ref.OwnerUID,
				BlockOwnerDeletion: &blockOwnerDeletion,
				Controller:         &isController,
			},
		}
	}

	return secret
}

// parseSecretData extracts CredentialData from a Kubernetes Secret's data map.
// A missing or empty credential key means the Secret carries no usable
// credential, which is reported as credentialstore.ErrNotFound so that callers
// treat an emptied Secret the same as a deleted one.
func parseSecretData(secret *corev1.Secret, key string) (*credentialstore.CredentialData, error) {
	credKey := key
	if credKey == "" {
		credKey = SecretKeyCredential
	}

	credBytes, ok := secret.Data[credKey]
	if !ok || len(credBytes) == 0 {
		return nil, fmt.Errorf("secret %s/%s does not contain key %q: %w",
			secret.Namespace, secret.Name, credKey, credentialstore.ErrNotFound)
	}

	data := &credentialstore.CredentialData{
		Credential: credBytes,
		Format:     string(secret.Data[SecretKeyFormat]),
	}

	if expiryStr, ok := secret.Data[SecretKeyExpiryTimestamp]; ok {
		ts, err := strconv.ParseInt(string(expiryStr), 10, 64)
		if err == nil && ts > 0 {
			data.ExpiryTime = unixToTime(ts)
		}
	}

	if iatStr, ok := secret.Data[SecretKeyIssuedAtTimestamp]; ok {
		ts, err := strconv.ParseInt(string(iatStr), 10, 64)
		if err == nil && ts > 0 {
			data.IssuedAt = unixToTime(ts)
		}
	}

	if prevCred, ok := secret.Data[SecretKeyPreviousCredential]; ok {
		data.PreviousCredential = prevCred
	}

	return data, nil
}

// unixToTime converts a Unix timestamp (seconds since epoch) to a time.Time.
func unixToTime(ts int64) time.Time {
	return time.Unix(ts, 0)
}

// mergeLabels merges source labels into target, preserving existing labels
// not present in source.
func mergeLabels(target *corev1.Secret, source map[string]string) {
	if target.Labels == nil {
		target.Labels = make(map[string]string)
	}
	maps.Copy(target.Labels, source)
}

// mergeAnnotations merges source annotations into target, preserving
// existing annotations not present in source.
func mergeAnnotations(target *corev1.Secret, source map[string]string) {
	if target.Annotations == nil {
		target.Annotations = make(map[string]string)
	}
	maps.Copy(target.Annotations, source)
}
