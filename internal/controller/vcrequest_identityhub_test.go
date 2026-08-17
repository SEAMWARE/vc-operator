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
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	vcv1alpha1 "github.com/wistefan/vc-operator/api/v1alpha1"
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
