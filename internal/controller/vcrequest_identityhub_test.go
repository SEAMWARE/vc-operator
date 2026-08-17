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

package controller

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	vcv1alpha1 "github.com/wistefan/vc-operator/api/v1alpha1"
	"github.com/wistefan/vc-operator/internal/credentialstore"
	"github.com/wistefan/vc-operator/internal/identityhub"
)

// recordingPublisher captures what the reconciler asked to publish.
type recordingPublisher struct {
	target identityhub.Target
	rawVC  string
	vc     json.RawMessage
	err    error
	calls  int
}

func (p *recordingPublisher) Publish(_ context.Context, target identityhub.Target, rawVC string, vc json.RawMessage) error {
	p.calls++
	p.target, p.rawVC, p.vc = target, rawVC, vc
	return p.err
}

func newIdentityHubTestReconciler(publisher IdentityHubPublisher, objs ...client.Object) *VerifiableCredentialRequestReconciler {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = vcv1alpha1.AddToScheme(scheme)

	return &VerifiableCredentialRequestReconciler{
		Client:               fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build(),
		Scheme:               scheme,
		IdentityHubPublisher: publisher,
	}
}

func apiKeySecret() *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "identityhub-secret", Namespace: "provider"},
		// A trailing newline is what a `kubectl create secret --from-file` or an
		// echo-based bootstrap leaves behind, and it must not end up in the header.
		Data: map[string][]byte{"superuser": []byte("c3VwZXItdXNlcg==.secret\n")},
	}
}

func vcRequestWithIdentityHub(target *vcv1alpha1.IdentityHubTarget) *vcv1alpha1.VerifiableCredentialRequest {
	return &vcv1alpha1.VerifiableCredentialRequest{
		ObjectMeta: metav1.ObjectMeta{Name: "fdsc-edc-credential", Namespace: "provider"},
		Spec: vcv1alpha1.VerifiableCredentialRequestSpec{
			CredentialType: "membership-credential",
			IssuerRef:      vcv1alpha1.LocalObjectReference{Name: "keycloak-issuer"},
			TargetSecretRef: vcv1alpha1.TargetSecretReference{
				Name: "vc-fdsc-edc-credential",
				Key:  "credential",
			},
			IdentityHub: target,
		},
	}
}

// buildTestCredential builds a credential whose payload carries a vc claim.
func buildTestCredential() string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","kid":"did:web:example.org#key-1"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"did:web:example.org","vc":{"type":["VerifiableCredential"],"issuer":"did:web:example.org"}}`))
	return header + "." + payload + ".signature"
}

func TestPublishToIdentityHub(t *testing.T) {
	publisher := &recordingPublisher{}
	vcReq := vcRequestWithIdentityHub(&vcv1alpha1.IdentityHubTarget{
		URL:           "http://identityhub-service:8082/api/identity/v1alpha",
		ParticipantID: "did:web:example.org",
		APIKeyRef:     vcv1alpha1.SecretKeyReference{Name: "identityhub-secret", Key: "superuser"},
		CredentialID:  "membership-credential",
	})
	r := newIdentityHubTestReconciler(publisher, apiKeySecret(), vcReq)

	credStr := buildTestCredential()
	if err := r.publishToIdentityHub(context.Background(), vcReq, credStr); err != nil {
		t.Fatalf("publishToIdentityHub() returned %v", err)
	}

	if publisher.calls != 1 {
		t.Fatalf("publisher called %d times, want 1", publisher.calls)
	}
	if publisher.target.APIKey != "c3VwZXItdXNlcg==.secret" {
		t.Errorf("api key = %q, want it trimmed of whitespace", publisher.target.APIKey)
	}
	if publisher.target.CredentialID != "membership-credential" {
		t.Errorf("credential id = %q", publisher.target.CredentialID)
	}
	if publisher.rawVC != credStr {
		t.Errorf("rawVC = %q, want the compact credential", publisher.rawVC)
	}
	// The published object is the credential, not the enclosing JWT claims.
	var vc map[string]any
	if err := json.Unmarshal(publisher.vc, &vc); err != nil {
		t.Fatalf("published vc is not valid JSON: %v", err)
	}
	if _, unexpected := vc["iss"]; unexpected {
		t.Errorf("published the JWT claims instead of the vc object: %s", publisher.vc)
	}
}

// The credential id has to be stable across renewals, so that a renewal replaces
// the stored copy instead of piling up entries.
func TestPublishToIdentityHubDefaultsTheCredentialIDToTheRequestName(t *testing.T) {
	publisher := &recordingPublisher{}
	vcReq := vcRequestWithIdentityHub(&vcv1alpha1.IdentityHubTarget{
		URL:           "http://identityhub-service:8082/api/identity/v1alpha",
		ParticipantID: "did:web:example.org",
		APIKeyRef:     vcv1alpha1.SecretKeyReference{Name: "identityhub-secret", Key: "superuser"},
	})
	r := newIdentityHubTestReconciler(publisher, apiKeySecret(), vcReq)

	if err := r.publishToIdentityHub(context.Background(), vcReq, buildTestCredential()); err != nil {
		t.Fatalf("publishToIdentityHub() returned %v", err)
	}
	if publisher.target.CredentialID != "fdsc-edc-credential" {
		t.Errorf("credential id = %q, want the request name", publisher.target.CredentialID)
	}
}

func TestPublishToIdentityHubFailsWithoutAPublisher(t *testing.T) {
	vcReq := vcRequestWithIdentityHub(&vcv1alpha1.IdentityHubTarget{
		URL:           "http://identityhub-service:8082/api/identity/v1alpha",
		ParticipantID: "did:web:example.org",
		APIKeyRef:     vcv1alpha1.SecretKeyReference{Name: "identityhub-secret", Key: "superuser"},
	})
	r := newIdentityHubTestReconciler(nil, apiKeySecret(), vcReq)

	err := r.publishToIdentityHub(context.Background(), vcReq, buildTestCredential())
	if err == nil || !strings.Contains(err.Error(), "no IdentityHub publisher") {
		t.Errorf("error = %v, want a missing-publisher error", err)
	}
}

func TestPublishToIdentityHubReportsSecretProblems(t *testing.T) {
	tests := map[string]struct {
		secret *corev1.Secret
		ref    vcv1alpha1.SecretKeyReference
		want   string
	}{
		"missing secret": {
			secret: apiKeySecret(),
			ref:    vcv1alpha1.SecretKeyReference{Name: "absent", Key: "superuser"},
			want:   "failed to read secret",
		},
		"missing key": {
			secret: apiKeySecret(),
			ref:    vcv1alpha1.SecretKeyReference{Name: "identityhub-secret", Key: "absent"},
			want:   "has no key",
		},
		"empty value": {
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "identityhub-secret", Namespace: "provider"},
				Data:       map[string][]byte{"superuser": {}},
			},
			ref:  vcv1alpha1.SecretKeyReference{Name: "identityhub-secret", Key: "superuser"},
			want: "is empty",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			vcReq := vcRequestWithIdentityHub(&vcv1alpha1.IdentityHubTarget{
				URL:           "http://identityhub-service:8082/api/identity/v1alpha",
				ParticipantID: "did:web:example.org",
				APIKeyRef:     tc.ref,
			})
			r := newIdentityHubTestReconciler(&recordingPublisher{}, tc.secret, vcReq)

			err := r.publishToIdentityHub(context.Background(), vcReq, buildTestCredential())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestPublishToIdentityHubFailsOnACredentialWithoutAVCClaim(t *testing.T) {
	publisher := &recordingPublisher{}
	vcReq := vcRequestWithIdentityHub(&vcv1alpha1.IdentityHubTarget{
		URL:           "http://identityhub-service:8082/api/identity/v1alpha",
		ParticipantID: "did:web:example.org",
		APIKeyRef:     vcv1alpha1.SecretKeyReference{Name: "identityhub-secret", Key: "superuser"},
	})
	r := newIdentityHubTestReconciler(publisher, apiKeySecret(), vcReq)

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"did:web:example.org"}`))

	err := r.publishToIdentityHub(context.Background(), vcReq, header+"."+payload+".sig")
	if err == nil || !strings.Contains(err.Error(), "credential object") {
		t.Errorf("error = %v, want an extraction failure", err)
	}
	if publisher.calls != 0 {
		t.Error("published a credential whose object could not be extracted")
	}
}

// storedOnlyCredentialStore serves a credential that is already stored and
// records whether anything tried to write a new one.
type storedOnlyCredentialStore struct {
	stored     []byte
	storeCalls int
}

func (s *storedOnlyCredentialStore) Store(_ context.Context, _ credentialstore.TargetRef, data *credentialstore.CredentialData) error {
	s.storeCalls++
	s.stored = data.Credential
	return nil
}

func (s *storedOnlyCredentialStore) Retrieve(_ context.Context, _ credentialstore.TargetRef) (*credentialstore.CredentialData, error) {
	if len(s.stored) == 0 {
		return nil, credentialstore.ErrNotFound
	}
	return &credentialstore.CredentialData{Credential: s.stored, Format: "jwt_vc_json"}, nil
}

func (s *storedOnlyCredentialStore) Delete(_ context.Context, _ credentialstore.TargetRef) error {
	return nil
}

// publishFailedRequest builds a request left in the state a failed publication
// produces: the credential was obtained and stored, the IdentityHub copy was
// not, and renewal is still far away.
func publishFailedRequest(clock *FakeClock) *vcv1alpha1.VerifiableCredentialRequest {
	vcReq := vcRequestWithIdentityHub(&vcv1alpha1.IdentityHubTarget{
		URL:           "http://identityhub-service:8082/api/identity/v1alpha",
		ParticipantID: "did:web:example.org",
		APIKeyRef:     vcv1alpha1.SecretKeyReference{Name: "identityhub-secret", Key: "superuser"},
		CredentialID:  "membership-credential",
	})
	vcReq.Generation = 1

	issuedAt := metav1.NewTime(clock.Now())
	renewal := metav1.NewTime(clock.Now().Add(1 * time.Hour))
	vcReq.Status.LastIssuanceTime = &issuedAt
	vcReq.Status.NextRenewalTime = &renewal
	vcReq.Status.Conditions = []metav1.Condition{
		{
			Type:               vcv1alpha1.ConditionTypeReady,
			Status:             metav1.ConditionFalse,
			Reason:             vcv1alpha1.ReasonIdentityHubPublishFailed,
			Message:            "Failed to publish credential to the identityhub",
			ObservedGeneration: 1,
			LastTransitionTime: issuedAt,
		},
	}
	return vcReq
}

func TestNeedsIdentityHubPublishOnly(t *testing.T) {
	clock := &FakeClock{CurrentTime: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)}
	r := &VerifiableCredentialRequestReconciler{Clock: clock}

	tests := []struct {
		name              string
		mutate            func(*vcv1alpha1.VerifiableCredentialRequest)
		credentialMissing bool
		want              bool
	}{
		{
			name: "publication is the only outstanding step",
			want: true,
		},
		{
			name:              "credential is gone, so it has to be re-issued",
			credentialMissing: true,
			want:              false,
		},
		{
			name: "no identityhub requested",
			mutate: func(v *vcv1alpha1.VerifiableCredentialRequest) {
				v.Spec.IdentityHub = nil
			},
			want: false,
		},
		{
			name: "the failure was not the publication step",
			mutate: func(v *vcv1alpha1.VerifiableCredentialRequest) {
				v.Status.Conditions[0].Reason = vcv1alpha1.ReasonCredentialRequestFailed
			},
			want: false,
		},
		{
			name: "spec changed since the failure, so re-run the whole pipeline",
			mutate: func(v *vcv1alpha1.VerifiableCredentialRequest) {
				v.Generation = 2
			},
			want: false,
		},
		{
			name: "renewal is already due, so re-issue and republish",
			mutate: func(v *vcv1alpha1.VerifiableCredentialRequest) {
				past := metav1.NewTime(clock.Now().Add(-1 * time.Minute))
				v.Status.NextRenewalTime = &past
			},
			want: false,
		},
		{
			name: "no renewal scheduled means nothing is known about what is stored",
			mutate: func(v *vcv1alpha1.VerifiableCredentialRequest) {
				v.Status.NextRenewalTime = nil
			},
			want: false,
		},
		{
			name: "a healthy request needs nothing",
			mutate: func(v *vcv1alpha1.VerifiableCredentialRequest) {
				v.Status.Conditions[0].Status = metav1.ConditionTrue
				v.Status.Conditions[0].Reason = vcv1alpha1.ReasonCredentialObtained
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vcReq := publishFailedRequest(clock)
			if tt.mutate != nil {
				tt.mutate(vcReq)
			}
			if got := r.needsIdentityHubPublishOnly(vcReq, tt.credentialMissing); got != tt.want {
				t.Errorf("needsIdentityHubPublishOnly() = %v, want %v", got, tt.want)
			}
		})
	}
}

// The point of the publish-only path: a transient IdentityHub outage must not
// make the operator mint a brand-new credential from the issuer on every retry.
func TestReconcileRetriesOnlyThePublicationAfterAPublishFailure(t *testing.T) {
	clock := &FakeClock{CurrentTime: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)}
	vcReq := publishFailedRequest(clock)
	credStr := buildTestCredential()

	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = vcv1alpha1.AddToScheme(scheme)

	store := &storedOnlyCredentialStore{stored: []byte(credStr)}
	publisher := &recordingPublisher{}
	r := &VerifiableCredentialRequestReconciler{
		Client: fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(apiKeySecret(), vcReq).
			WithStatusSubresource(&vcv1alpha1.VerifiableCredentialRequest{}).
			Build(),
		Scheme:          scheme,
		CredentialStore: store,
		// Every method of this mock errors when unconfigured, so any fall-through
		// to the issuance pipeline fails the reconciliation below.
		OID4VCIClient:        &mockOID4VCIClient{},
		IdentityHubPublisher: publisher,
		EventRecorder:        events.NewFakeRecorder(fakeEventBufferSize),
		Clock:                clock,
	}

	key := types.NamespacedName{Name: vcReq.Name, Namespace: vcReq.Namespace}
	result, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: key})
	if err != nil {
		t.Fatalf("Reconcile() returned %v; it must not have gone back to the issuer", err)
	}

	if publisher.calls != 1 {
		t.Errorf("publisher called %d times, want 1", publisher.calls)
	}
	if publisher.rawVC != credStr {
		t.Errorf("republished %q, want the already-stored credential", publisher.rawVC)
	}
	if store.storeCalls != 0 {
		t.Errorf("Store called %d times, want 0: the stored credential is still valid and its "+
			"rotation buffer must not be overwritten", store.storeCalls)
	}
	if result.RequeueAfter <= 0 {
		t.Errorf("RequeueAfter = %v, want the remaining time until renewal", result.RequeueAfter)
	}

	var updated vcv1alpha1.VerifiableCredentialRequest
	if err := r.Get(context.Background(), key, &updated); err != nil {
		t.Fatalf("failed to read back the request: %v", err)
	}
	if c := meta.FindStatusCondition(updated.Status.Conditions, vcv1alpha1.ConditionTypeReady); c == nil || c.Status != metav1.ConditionTrue {
		t.Errorf("Ready = %v, want True once the copy is in place", c)
	}
	if c := meta.FindStatusCondition(updated.Status.Conditions, vcv1alpha1.ConditionTypeIdentityHubPublished); c == nil || c.Status != metav1.ConditionTrue {
		t.Errorf("IdentityHubPublished = %v, want True", c)
	}
	// Republishing is not a new issuance.
	if updated.Status.RenewalCount != 0 {
		t.Errorf("RenewalCount = %d, want 0", updated.Status.RenewalCount)
	}
}

// A failed publication must not leave IdentityHubPublished claiming the copy is
// in place, otherwise the condition reports a credential the hub does not hold.
func TestIdentityHubPublishFailureMarksTheCopyOutOfSync(t *testing.T) {
	clock := &FakeClock{CurrentTime: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)}
	vcReq := publishFailedRequest(clock)
	// Start from the state left by a previous, successful publication.
	meta.SetStatusCondition(&vcReq.Status.Conditions, metav1.Condition{
		Type:               vcv1alpha1.ConditionTypeIdentityHubPublished,
		Status:             metav1.ConditionTrue,
		Reason:             vcv1alpha1.ReasonIdentityHubPublished,
		Message:            "Credential published",
		ObservedGeneration: 1,
	})

	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = vcv1alpha1.AddToScheme(scheme)

	r := &VerifiableCredentialRequestReconciler{
		Client: fake.NewClientBuilder().WithScheme(scheme).
			WithObjects(apiKeySecret(), vcReq).
			WithStatusSubresource(&vcv1alpha1.VerifiableCredentialRequest{}).
			Build(),
		Scheme:               scheme,
		CredentialStore:      &storedOnlyCredentialStore{stored: []byte(buildTestCredential())},
		OID4VCIClient:        &mockOID4VCIClient{},
		IdentityHubPublisher: &recordingPublisher{err: errors.New("identityhub unreachable")},
		EventRecorder:        events.NewFakeRecorder(fakeEventBufferSize),
		Clock:                clock,
	}

	key := types.NamespacedName{Name: vcReq.Name, Namespace: vcReq.Namespace}
	if _, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: key}); err == nil {
		t.Fatal("Reconcile() returned nil, want the publish error so it is retried with backoff")
	}

	var updated vcv1alpha1.VerifiableCredentialRequest
	if err := r.Get(context.Background(), key, &updated); err != nil {
		t.Fatalf("failed to read back the request: %v", err)
	}
	c := meta.FindStatusCondition(updated.Status.Conditions, vcv1alpha1.ConditionTypeIdentityHubPublished)
	if c == nil || c.Status != metav1.ConditionFalse {
		t.Errorf("IdentityHubPublished = %v, want False after a failed publication", c)
	}
}
