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

package kubernetes

import (
	"context"
	"strconv"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/SEAMWARE/vc-operator/internal/credentialstore"
)

// newTestScheme creates a runtime scheme with the core v1 types registered.
func newTestScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	return scheme
}

// newTestStore creates a SecretStore backed by a fake Kubernetes client
// with the given initial objects.
func newTestStore(objs ...client.Object) *SecretStore {
	scheme := newTestScheme()
	builder := fake.NewClientBuilder().WithScheme(scheme)
	if len(objs) > 0 {
		builder = builder.WithObjects(objs...)
	}
	return NewSecretStore(builder.Build())
}

func TestSecretStore_StoreAndRetrieve(t *testing.T) {
	ctx := context.Background()
	store := newTestStore()
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	expiry := now.Add(2 * time.Hour)

	ref := credentialstore.TargetRef{
		Namespace: "default",
		Name:      "test-credential",
		Key:       "credential",
		OwnerGVK: metav1.GroupVersionKind{
			Group:   "vc.vc-operator.io",
			Version: "v1alpha1",
			Kind:    "VerifiableCredentialRequest",
		},
		OwnerUID:  types.UID("test-uid-123"),
		OwnerName: "my-vcr",
	}

	data := &credentialstore.CredentialData{
		Credential: []byte("eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.sig"),
		Format:     "jwt_vc_json",
		ExpiryTime: expiry,
		IssuedAt:   now,
	}

	// Store the credential.
	if err := store.Store(ctx, ref, data); err != nil {
		t.Fatalf("Store() error = %v", err)
	}

	// Retrieve and verify.
	retrieved, err := store.Retrieve(ctx, ref)
	if err != nil {
		t.Fatalf("Retrieve() error = %v", err)
	}

	if string(retrieved.Credential) != string(data.Credential) {
		t.Errorf("Credential = %q, want %q", string(retrieved.Credential), string(data.Credential))
	}
	if retrieved.Format != data.Format {
		t.Errorf("Format = %q, want %q", retrieved.Format, data.Format)
	}
	if retrieved.ExpiryTime.Unix() != data.ExpiryTime.Unix() {
		t.Errorf("ExpiryTime = %v, want %v", retrieved.ExpiryTime, data.ExpiryTime)
	}
	if retrieved.IssuedAt.Unix() != data.IssuedAt.Unix() {
		t.Errorf("IssuedAt = %v, want %v", retrieved.IssuedAt, data.IssuedAt)
	}
}

func TestSecretStore_StoreUpdatesExisting(t *testing.T) {
	ctx := context.Background()

	// Pre-create an existing secret.
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-credential",
			Namespace: "default",
			Labels: map[string]string{
				"custom-label": "custom-value",
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"credential": []byte("old-credential"),
			"format":     []byte("jwt_vc_json"),
		},
	}

	store := newTestStore(existing)

	ref := credentialstore.TargetRef{
		Namespace: "default",
		Name:      "test-credential",
		Key:       "credential",
	}

	newData := &credentialstore.CredentialData{
		Credential: []byte("new-credential"),
		Format:     "jwt_vc_json",
	}

	// Update the credential.
	if err := store.Store(ctx, ref, newData); err != nil {
		t.Fatalf("Store() update error = %v", err)
	}

	// Retrieve and verify the update.
	retrieved, err := store.Retrieve(ctx, ref)
	if err != nil {
		t.Fatalf("Retrieve() error = %v", err)
	}

	if string(retrieved.Credential) != "new-credential" {
		t.Errorf("Credential = %q, want %q", string(retrieved.Credential), "new-credential")
	}
}

func TestSecretStore_StoreWithPreviousCredential(t *testing.T) {
	ctx := context.Background()
	store := newTestStore()

	ref := credentialstore.TargetRef{
		Namespace: "default",
		Name:      "test-rotation",
		Key:       "credential",
	}

	data := &credentialstore.CredentialData{
		Credential:         []byte("new-credential"),
		Format:             "jwt_vc_json",
		PreviousCredential: []byte("old-credential"),
	}

	if err := store.Store(ctx, ref, data); err != nil {
		t.Fatalf("Store() error = %v", err)
	}

	retrieved, err := store.Retrieve(ctx, ref)
	if err != nil {
		t.Fatalf("Retrieve() error = %v", err)
	}

	if string(retrieved.PreviousCredential) != "old-credential" {
		t.Errorf("PreviousCredential = %q, want %q", string(retrieved.PreviousCredential), "old-credential")
	}
}

func TestSecretStore_StoreWithCustomKey(t *testing.T) {
	ctx := context.Background()
	store := newTestStore()

	ref := credentialstore.TargetRef{
		Namespace: "default",
		Name:      "test-custom-key",
		Key:       "my-vc",
	}

	data := &credentialstore.CredentialData{
		Credential: []byte("custom-key-credential"),
		Format:     "jwt_vc_json",
	}

	if err := store.Store(ctx, ref, data); err != nil {
		t.Fatalf("Store() error = %v", err)
	}

	retrieved, err := store.Retrieve(ctx, ref)
	if err != nil {
		t.Fatalf("Retrieve() error = %v", err)
	}

	if string(retrieved.Credential) != "custom-key-credential" {
		t.Errorf("Credential = %q, want %q", string(retrieved.Credential), "custom-key-credential")
	}
}

func TestSecretStore_RetrieveNotFound(t *testing.T) {
	ctx := context.Background()
	store := newTestStore()

	ref := credentialstore.TargetRef{
		Namespace: "default",
		Name:      "nonexistent",
	}

	_, err := store.Retrieve(ctx, ref)
	if err == nil {
		t.Fatal("expected error for nonexistent secret, got nil")
	}
}

func TestSecretStore_Delete(t *testing.T) {
	ctx := context.Background()

	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "to-delete",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"credential": []byte("cred"),
		},
	}
	store := newTestStore(existing)

	ref := credentialstore.TargetRef{
		Namespace: "default",
		Name:      "to-delete",
	}

	// Delete the secret.
	if err := store.Delete(ctx, ref); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Verify it's gone.
	_, err := store.Retrieve(ctx, ref)
	if err == nil {
		t.Fatal("expected error after delete, got nil")
	}
}

func TestSecretStore_DeleteNonexistent(t *testing.T) {
	ctx := context.Background()
	store := newTestStore()

	ref := credentialstore.TargetRef{
		Namespace: "default",
		Name:      "does-not-exist",
	}

	// Deleting a nonexistent secret should not return an error (idempotent).
	if err := store.Delete(ctx, ref); err != nil {
		t.Fatalf("Delete() of nonexistent secret should be idempotent, got error: %v", err)
	}
}

func TestSecretStore_StoreValidationErrors(t *testing.T) {
	ctx := context.Background()
	store := newTestStore()

	tests := []struct {
		name string
		ref  credentialstore.TargetRef
	}{
		{
			name: "empty name",
			ref: credentialstore.TargetRef{
				Namespace: "default",
				Name:      "",
			},
		},
		{
			name: "empty namespace",
			ref: credentialstore.TargetRef{
				Namespace: "",
				Name:      "test",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := &credentialstore.CredentialData{
				Credential: []byte("cred"),
				Format:     "jwt_vc_json",
			}
			if err := store.Store(ctx, tt.ref, data); err == nil {
				t.Fatal("expected validation error, got nil")
			}
		})
	}
}

func TestBuildSecret_Labels(t *testing.T) {
	ref := credentialstore.TargetRef{
		Namespace: "default",
		Name:      "test-secret",
		Key:       "credential",
	}

	data := &credentialstore.CredentialData{
		Credential: []byte("cred"),
		Format:     "jwt_vc_json",
	}

	secret := buildSecret(ref, data)

	if secret.Labels[LabelManagedBy] != LabelManagedByValue {
		t.Errorf("Label %s = %q, want %q", LabelManagedBy, secret.Labels[LabelManagedBy], LabelManagedByValue)
	}
	if secret.Labels[LabelComponent] != LabelComponentValue {
		t.Errorf("Label %s = %q, want %q", LabelComponent, secret.Labels[LabelComponent], LabelComponentValue)
	}
}

func TestBuildSecret_OwnerReferences(t *testing.T) {
	ref := credentialstore.TargetRef{
		Namespace: "default",
		Name:      "test-secret",
		Key:       "credential",
		OwnerGVK: metav1.GroupVersionKind{
			Group:   "vc.vc-operator.io",
			Version: "v1alpha1",
			Kind:    "VerifiableCredentialRequest",
		},
		OwnerUID:  types.UID("uid-456"),
		OwnerName: "my-vcr",
	}

	data := &credentialstore.CredentialData{
		Credential: []byte("cred"),
		Format:     "jwt_vc_json",
	}

	secret := buildSecret(ref, data)

	if len(secret.OwnerReferences) != 1 {
		t.Fatalf("expected 1 owner reference, got %d", len(secret.OwnerReferences))
	}

	ownerRef := secret.OwnerReferences[0]
	if ownerRef.APIVersion != "vc.vc-operator.io/v1alpha1" {
		t.Errorf("OwnerRef APIVersion = %q, want %q", ownerRef.APIVersion, "vc.vc-operator.io/v1alpha1")
	}
	if ownerRef.Kind != "VerifiableCredentialRequest" {
		t.Errorf("OwnerRef Kind = %q, want %q", ownerRef.Kind, "VerifiableCredentialRequest")
	}
	if ownerRef.Name != "my-vcr" {
		t.Errorf("OwnerRef Name = %q, want %q", ownerRef.Name, "my-vcr")
	}
	if ownerRef.UID != types.UID("uid-456") {
		t.Errorf("OwnerRef UID = %q, want %q", ownerRef.UID, "uid-456")
	}
	if ownerRef.Controller == nil || !*ownerRef.Controller {
		t.Error("OwnerRef.Controller should be true")
	}
	if ownerRef.BlockOwnerDeletion == nil || !*ownerRef.BlockOwnerDeletion {
		t.Error("OwnerRef.BlockOwnerDeletion should be true")
	}
}

func TestBuildSecret_NoOwnerReference(t *testing.T) {
	ref := credentialstore.TargetRef{
		Namespace: "default",
		Name:      "test-secret",
		Key:       "credential",
	}

	data := &credentialstore.CredentialData{
		Credential: []byte("cred"),
		Format:     "jwt_vc_json",
	}

	secret := buildSecret(ref, data)

	if len(secret.OwnerReferences) != 0 {
		t.Fatalf("expected 0 owner references, got %d", len(secret.OwnerReferences))
	}
}

func TestBuildSecret_DataKeys(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	expiry := now.Add(2 * time.Hour)

	tests := []struct {
		name              string
		key               string
		data              *credentialstore.CredentialData
		wantCredKey       string
		wantExpiryPresent bool
		wantIatPresent    bool
		wantPrevPresent   bool
	}{
		{
			name: "all fields present with default key",
			key:  "",
			data: &credentialstore.CredentialData{
				Credential:         []byte("cred"),
				Format:             "jwt_vc_json",
				ExpiryTime:         expiry,
				IssuedAt:           now,
				PreviousCredential: []byte("old"),
			},
			wantCredKey:       SecretKeyCredential,
			wantExpiryPresent: true,
			wantIatPresent:    true,
			wantPrevPresent:   true,
		},
		{
			name: "custom key and no optional fields",
			key:  "my-key",
			data: &credentialstore.CredentialData{
				Credential: []byte("cred"),
				Format:     "jwt_vc_json",
			},
			wantCredKey:       "my-key",
			wantExpiryPresent: false,
			wantIatPresent:    false,
			wantPrevPresent:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref := credentialstore.TargetRef{
				Namespace: "default",
				Name:      "test",
				Key:       tt.key,
			}

			secret := buildSecret(ref, tt.data)

			if _, ok := secret.Data[tt.wantCredKey]; !ok {
				t.Errorf("expected data key %q to be present", tt.wantCredKey)
			}
			if _, ok := secret.Data[SecretKeyFormat]; !ok {
				t.Error("expected format key to be present")
			}

			_, hasExpiry := secret.Data[SecretKeyExpiryTimestamp]
			if hasExpiry != tt.wantExpiryPresent {
				t.Errorf("expiry key present = %v, want %v", hasExpiry, tt.wantExpiryPresent)
			}

			_, hasIat := secret.Data[SecretKeyIssuedAtTimestamp]
			if hasIat != tt.wantIatPresent {
				t.Errorf("issuedAt key present = %v, want %v", hasIat, tt.wantIatPresent)
			}

			_, hasPrev := secret.Data[SecretKeyPreviousCredential]
			if hasPrev != tt.wantPrevPresent {
				t.Errorf("previousCredential key present = %v, want %v", hasPrev, tt.wantPrevPresent)
			}

			if tt.wantExpiryPresent {
				ts := string(secret.Data[SecretKeyExpiryTimestamp])
				wantTS := strconv.FormatInt(tt.data.ExpiryTime.Unix(), 10)
				if ts != wantTS {
					t.Errorf("expiry timestamp = %q, want %q", ts, wantTS)
				}
			}
		})
	}
}

func TestBuildSecret_Annotations(t *testing.T) {
	ref := credentialstore.TargetRef{
		Namespace: "default",
		Name:      "test-secret",
		Key:       "credential",
		OwnerName: "my-vcr",
	}

	data := &credentialstore.CredentialData{
		Credential: []byte("cred"),
		Format:     "jwt_vc_json",
	}

	secret := buildSecret(ref, data)

	if secret.Annotations[AnnotationSourceCR] != "my-vcr" {
		t.Errorf("Annotation %s = %q, want %q", AnnotationSourceCR, secret.Annotations[AnnotationSourceCR], "my-vcr")
	}
}

func TestBuildSecret_SecretType(t *testing.T) {
	ref := credentialstore.TargetRef{
		Namespace: "default",
		Name:      "test-secret",
	}

	data := &credentialstore.CredentialData{
		Credential: []byte("cred"),
		Format:     "jwt_vc_json",
	}

	secret := buildSecret(ref, data)

	if secret.Type != corev1.SecretTypeOpaque {
		t.Errorf("Secret type = %q, want %q", secret.Type, corev1.SecretTypeOpaque)
	}
}
