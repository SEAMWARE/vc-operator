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
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	vcv1alpha1 "github.com/SEAMWARE/vc-operator/api/v1alpha1"
	"github.com/SEAMWARE/vc-operator/internal/oid4vci"
)

// fakeEventBufferSize is the buffer size for the fake event recorder channel.
const fakeEventBufferSize = 20

// mockOID4VCIClient is a configurable mock implementation of oid4vci.Client
// for testing the CredentialIssuer controller without real HTTP calls.
type mockOID4VCIClient struct {
	discoverMetadataFunc      func(ctx context.Context, issuerURL string) (*oid4vci.IssuerMetadata, error)
	obtainAccessTokenFunc     func(ctx context.Context, tokenURL string, auth oid4vci.TokenAuth) (*oid4vci.TokenResponse, error)
	requestCredentialFunc     func(ctx context.Context, credentialURL string, accessToken string, request oid4vci.CredentialRequest) (*oid4vci.CredentialResponse, error)
	createCredentialOfferFunc func(ctx context.Context, issuerURL, accessToken, credentialConfigID string) (*oid4vci.CredentialOfferURI, error)
	fetchCredentialOfferFunc  func(ctx context.Context, issuerURL, nonce string) (*oid4vci.CredentialOffer, error)
	fetchNonceFunc            func(ctx context.Context, nonceEndpoint, accessToken string) (string, error)
}

// DiscoverMetadata delegates to the configured mock function or returns an error.
func (m *mockOID4VCIClient) DiscoverMetadata(ctx context.Context, issuerURL string) (*oid4vci.IssuerMetadata, error) {
	if m.discoverMetadataFunc != nil {
		return m.discoverMetadataFunc(ctx, issuerURL)
	}
	return nil, fmt.Errorf("DiscoverMetadata not configured")
}

// ObtainAccessToken delegates to the configured mock function or returns an error.
func (m *mockOID4VCIClient) ObtainAccessToken(ctx context.Context, tokenURL string, auth oid4vci.TokenAuth) (*oid4vci.TokenResponse, error) {
	if m.obtainAccessTokenFunc != nil {
		return m.obtainAccessTokenFunc(ctx, tokenURL, auth)
	}
	return nil, fmt.Errorf("ObtainAccessToken not configured")
}

// RequestCredential delegates to the configured mock function or returns an error.
func (m *mockOID4VCIClient) RequestCredential(ctx context.Context, credentialURL string, accessToken string, request oid4vci.CredentialRequest) (*oid4vci.CredentialResponse, error) {
	if m.requestCredentialFunc != nil {
		return m.requestCredentialFunc(ctx, credentialURL, accessToken, request)
	}
	return nil, fmt.Errorf("RequestCredential not configured")
}

// CreateCredentialOffer delegates to the configured mock function or returns an error.
func (m *mockOID4VCIClient) CreateCredentialOffer(ctx context.Context, issuerURL, accessToken, credentialConfigID string) (*oid4vci.CredentialOfferURI, error) {
	if m.createCredentialOfferFunc != nil {
		return m.createCredentialOfferFunc(ctx, issuerURL, accessToken, credentialConfigID)
	}
	return nil, fmt.Errorf("CreateCredentialOffer not configured")
}

// FetchCredentialOffer delegates to the configured mock function or returns an error.
func (m *mockOID4VCIClient) FetchCredentialOffer(ctx context.Context, issuerURL, nonce string) (*oid4vci.CredentialOffer, error) {
	if m.fetchCredentialOfferFunc != nil {
		return m.fetchCredentialOfferFunc(ctx, issuerURL, nonce)
	}
	return nil, fmt.Errorf("FetchCredentialOffer not configured")
}

// FetchNonce delegates to the configured mock function or returns an error.
func (m *mockOID4VCIClient) FetchNonce(ctx context.Context, nonceEndpoint, accessToken string) (string, error) {
	if m.fetchNonceFunc != nil {
		return m.fetchNonceFunc(ctx, nonceEndpoint, accessToken)
	}
	return "", fmt.Errorf("FetchNonce not configured")
}

// defaultMetadata returns a well-formed IssuerMetadata for use in tests.
func defaultMetadata() *oid4vci.IssuerMetadata {
	return &oid4vci.IssuerMetadata{
		CredentialIssuer:   "https://issuer.example.com",
		CredentialEndpoint: "https://issuer.example.com/credentials",
		TokenEndpoint:      "https://issuer.example.com/token",
		CredentialConfigurationsSupported: map[string]oid4vci.CredentialConfiguration{
			"VerifiableCredential": {
				Format: "jwt_vc_json",
			},
			"UniversityDegree": {
				Format: "jwt_vc_json",
			},
		},
	}
}

var _ = Describe("CredentialIssuer Controller", func() {
	const (
		issuerName = "test-issuer"
		issuerNs   = "default"
		secretName = "test-auth-secret"
		issuerURL  = "https://issuer.example.com"
	)

	var (
		typeNamespacedName types.NamespacedName
		mockClient         *mockOID4VCIClient
		eventRecorder      *events.FakeRecorder
		reconciler         *CredentialIssuerReconciler
	)

	BeforeEach(func() {
		typeNamespacedName = types.NamespacedName{
			Name:      issuerName,
			Namespace: issuerNs,
		}
		mockClient = &mockOID4VCIClient{}
		eventRecorder = events.NewFakeRecorder(fakeEventBufferSize)
		reconciler = &CredentialIssuerReconciler{
			Client:        k8sClient,
			Scheme:        k8sClient.Scheme(),
			OID4VCIClient: mockClient,
			EventRecorder: eventRecorder,
		}
	})

	// createIssuer creates a CredentialIssuer CR with the given spec.
	createIssuer := func(ctx context.Context, name string, spec vcv1alpha1.CredentialIssuerSpec) {
		resource := &vcv1alpha1.CredentialIssuer{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: issuerNs,
			},
			Spec: spec,
		}
		Expect(k8sClient.Create(ctx, resource)).To(Succeed())
	}

	// createSecret creates a Kubernetes Secret with the given data.
	createSecret := func(ctx context.Context, name string, data map[string][]byte) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: issuerNs,
			},
			Data: data,
		}
		Expect(k8sClient.Create(ctx, secret)).To(Succeed())
	}

	// deleteIssuer deletes a CredentialIssuer if it exists.
	deleteIssuer := func(ctx context.Context, name string) {
		resource := &vcv1alpha1.CredentialIssuer{}
		key := types.NamespacedName{Name: name, Namespace: issuerNs}
		if err := k8sClient.Get(ctx, key, resource); err == nil {
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		}
	}

	// deleteSecret deletes a Secret if it exists.
	deleteSecret := func(ctx context.Context, name string) {
		secret := &corev1.Secret{}
		key := types.NamespacedName{Name: name, Namespace: issuerNs}
		if err := k8sClient.Get(ctx, key, secret); err == nil {
			Expect(k8sClient.Delete(ctx, secret)).To(Succeed())
		}
	}

	// getIssuerStatus fetches the current CredentialIssuer and returns its status.
	getIssuerStatus := func(ctx context.Context, name string) vcv1alpha1.CredentialIssuerStatus {
		var issuer vcv1alpha1.CredentialIssuer
		key := types.NamespacedName{Name: name, Namespace: issuerNs}
		Expect(k8sClient.Get(ctx, key, &issuer)).To(Succeed())
		return issuer.Status
	}

	Context("when the CredentialIssuer resource is not found", func() {
		It("should return without error and not requeue", func() {
			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      "nonexistent",
					Namespace: issuerNs,
				},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ctrl.Result{}))
		})
	})

	Context("when the auth Secret is not found", func() {
		BeforeEach(func() {
			createIssuer(ctx, issuerName, vcv1alpha1.CredentialIssuerSpec{
				IssuerURL:     issuerURL,
				AuthSecretRef: vcv1alpha1.SecretReference{Name: secretName},
			})
		})

		AfterEach(func() {
			deleteIssuer(ctx, issuerName)
		})

		It("should set Ready=False with AuthSecretNotFound reason", func() {
			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(DefaultErrorRequeueInterval))

			status := getIssuerStatus(ctx, issuerName)

			readyCondition := meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeReady)
			Expect(readyCondition).NotTo(BeNil())
			Expect(readyCondition.Status).To(Equal(metav1.ConditionFalse))
			Expect(readyCondition.Reason).To(Equal(vcv1alpha1.ReasonAuthSecretNotFound))

			errorCondition := meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeError)
			Expect(errorCondition).NotTo(BeNil())
			Expect(errorCondition.Status).To(Equal(metav1.ConditionTrue))
			Expect(errorCondition.Reason).To(Equal(vcv1alpha1.ReasonAuthSecretNotFound))
		})

		It("should record a warning event for the missing auth Secret", func() {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			var event string
			Expect(eventRecorder.Events).Should(Receive(&event))
			Expect(event).To(ContainSubstring(vcv1alpha1.ReasonAuthSecretNotFound))
			Expect(event).To(ContainSubstring(secretName))
		})
	})

	Context("when the auth Secret is missing required keys", func() {
		BeforeEach(func() {
			createIssuer(ctx, issuerName, vcv1alpha1.CredentialIssuerSpec{
				IssuerURL:     issuerURL,
				AuthSecretRef: vcv1alpha1.SecretReference{Name: secretName},
			})
			createSecret(ctx, secretName, map[string][]byte{
				"unrelated_key": []byte("some-value"),
			})
		})

		AfterEach(func() {
			deleteIssuer(ctx, issuerName)
			deleteSecret(ctx, secretName)
		})

		It("should set Ready=False with AuthSecretInvalid reason", func() {
			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(DefaultErrorRequeueInterval))

			status := getIssuerStatus(ctx, issuerName)

			readyCondition := meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeReady)
			Expect(readyCondition).NotTo(BeNil())
			Expect(readyCondition.Status).To(Equal(metav1.ConditionFalse))
			Expect(readyCondition.Reason).To(Equal(vcv1alpha1.ReasonAuthSecretInvalid))

			errorCondition := meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeError)
			Expect(errorCondition).NotTo(BeNil())
			Expect(errorCondition.Status).To(Equal(metav1.ConditionTrue))
		})

		It("should record a warning event about invalid Secret keys", func() {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			var event string
			Expect(eventRecorder.Events).Should(Receive(&event))
			Expect(event).To(ContainSubstring(vcv1alpha1.ReasonAuthSecretInvalid))
		})
	})

	Context("when the auth Secret has empty values for required keys", func() {
		BeforeEach(func() {
			createIssuer(ctx, issuerName, vcv1alpha1.CredentialIssuerSpec{
				IssuerURL:     issuerURL,
				AuthSecretRef: vcv1alpha1.SecretReference{Name: secretName},
			})
			createSecret(ctx, secretName, map[string][]byte{
				AuthSecretKeyClientID:     []byte(""),
				AuthSecretKeyClientSecret: []byte(""),
			})
		})

		AfterEach(func() {
			deleteIssuer(ctx, issuerName)
			deleteSecret(ctx, secretName)
		})

		It("should reject secrets with empty values and set AuthSecretInvalid", func() {
			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(DefaultErrorRequeueInterval))

			status := getIssuerStatus(ctx, issuerName)
			readyCondition := meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeReady)
			Expect(readyCondition).NotTo(BeNil())
			Expect(readyCondition.Status).To(Equal(metav1.ConditionFalse))
			Expect(readyCondition.Reason).To(Equal(vcv1alpha1.ReasonAuthSecretInvalid))
		})
	})

	Context("when the auth Secret has only client_id without client_secret", func() {
		BeforeEach(func() {
			createIssuer(ctx, issuerName, vcv1alpha1.CredentialIssuerSpec{
				IssuerURL:     issuerURL,
				AuthSecretRef: vcv1alpha1.SecretReference{Name: secretName},
			})
			createSecret(ctx, secretName, map[string][]byte{
				AuthSecretKeyClientID: []byte("my-client"),
			})
		})

		AfterEach(func() {
			deleteIssuer(ctx, issuerName)
			deleteSecret(ctx, secretName)
		})

		It("should reject partial client credentials and set AuthSecretInvalid", func() {
			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(DefaultErrorRequeueInterval))

			status := getIssuerStatus(ctx, issuerName)
			readyCondition := meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeReady)
			Expect(readyCondition).NotTo(BeNil())
			Expect(readyCondition.Status).To(Equal(metav1.ConditionFalse))
			Expect(readyCondition.Reason).To(Equal(vcv1alpha1.ReasonAuthSecretInvalid))
		})
	})

	Context("when the auth Secret has valid client_credentials keys", func() {
		BeforeEach(func() {
			createIssuer(ctx, issuerName, vcv1alpha1.CredentialIssuerSpec{
				IssuerURL:     issuerURL,
				AuthSecretRef: vcv1alpha1.SecretReference{Name: secretName},
			})
			createSecret(ctx, secretName, map[string][]byte{
				AuthSecretKeyClientID:     []byte("my-client-id"),
				AuthSecretKeyClientSecret: []byte("my-client-secret"),
			})
			mockClient.discoverMetadataFunc = func(_ context.Context, _ string) (*oid4vci.IssuerMetadata, error) {
				return defaultMetadata(), nil
			}
		})

		AfterEach(func() {
			deleteIssuer(ctx, issuerName)
			deleteSecret(ctx, secretName)
		})

		It("should pass validation and set Ready=True", func() {
			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(MetadataRefreshInterval))

			status := getIssuerStatus(ctx, issuerName)
			readyCondition := meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeReady)
			Expect(readyCondition).NotTo(BeNil())
			Expect(readyCondition.Status).To(Equal(metav1.ConditionTrue))
			Expect(readyCondition.Reason).To(Equal(vcv1alpha1.ReasonMetadataDiscovered))
		})
	})

	Context("when the auth Secret has valid pre_authorized_code key", func() {
		BeforeEach(func() {
			createIssuer(ctx, issuerName, vcv1alpha1.CredentialIssuerSpec{
				IssuerURL:     issuerURL,
				AuthSecretRef: vcv1alpha1.SecretReference{Name: secretName},
			})
			createSecret(ctx, secretName, map[string][]byte{
				AuthSecretKeyPreAuthorizedCode: []byte("pre-auth-code-123"),
			})
			mockClient.discoverMetadataFunc = func(_ context.Context, _ string) (*oid4vci.IssuerMetadata, error) {
				return defaultMetadata(), nil
			}
		})

		AfterEach(func() {
			deleteIssuer(ctx, issuerName)
			deleteSecret(ctx, secretName)
		})

		It("should pass validation with pre-authorized code and set Ready=True", func() {
			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(MetadataRefreshInterval))

			status := getIssuerStatus(ctx, issuerName)
			readyCondition := meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeReady)
			Expect(readyCondition).NotTo(BeNil())
			Expect(readyCondition.Status).To(Equal(metav1.ConditionTrue))
		})
	})

	Context("when metadata discovery succeeds", func() {
		BeforeEach(func() {
			createIssuer(ctx, issuerName, vcv1alpha1.CredentialIssuerSpec{
				IssuerURL:     issuerURL,
				AuthSecretRef: vcv1alpha1.SecretReference{Name: secretName},
			})
			createSecret(ctx, secretName, map[string][]byte{
				AuthSecretKeyClientID:     []byte("my-client-id"),
				AuthSecretKeyClientSecret: []byte("my-client-secret"),
			})
			mockClient.discoverMetadataFunc = func(_ context.Context, _ string) (*oid4vci.IssuerMetadata, error) {
				return defaultMetadata(), nil
			}
		})

		AfterEach(func() {
			deleteIssuer(ctx, issuerName)
			deleteSecret(ctx, secretName)
		})

		It("should populate status with discovered metadata endpoints", func() {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			status := getIssuerStatus(ctx, issuerName)
			Expect(status.CredentialEndpoint).To(Equal("https://issuer.example.com/credentials"))
			Expect(status.TokenEndpoint).To(Equal("https://issuer.example.com/token"))
		})

		It("should populate supported credential types sorted alphabetically", func() {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			status := getIssuerStatus(ctx, issuerName)
			Expect(status.SupportedCredentialTypes).To(Equal([]string{
				"UniversityDegree",
				"VerifiableCredential",
			}))
		})

		It("should set the LastMetadataFetchTime", func() {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			status := getIssuerStatus(ctx, issuerName)
			Expect(status.LastMetadataFetchTime).NotTo(BeNil())
		})

		It("should requeue after MetadataRefreshInterval", func() {
			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(MetadataRefreshInterval))
		})

		It("should record a normal event for successful discovery", func() {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			var event string
			Expect(eventRecorder.Events).Should(Receive(&event))
			Expect(event).To(ContainSubstring(vcv1alpha1.ReasonMetadataDiscovered))
			Expect(event).To(ContainSubstring("credential_endpoint"))
		})

		It("should clear previous Error condition on success", func() {
			// First reconcile: make it fail to set Error condition.
			failingClient := &mockOID4VCIClient{
				discoverMetadataFunc: func(_ context.Context, _ string) (*oid4vci.IssuerMetadata, error) {
					return nil, fmt.Errorf("connection refused")
				},
			}
			failReconciler := &CredentialIssuerReconciler{
				Client:        k8sClient,
				Scheme:        k8sClient.Scheme(),
				OID4VCIClient: failingClient,
				EventRecorder: events.NewFakeRecorder(fakeEventBufferSize),
			}
			_, _ = failReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})

			// Verify Error condition was set.
			status := getIssuerStatus(ctx, issuerName)
			errorCondition := meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeError)
			Expect(errorCondition).NotTo(BeNil())
			Expect(errorCondition.Status).To(Equal(metav1.ConditionTrue))

			// Second reconcile: succeed, which should clear Error.
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			status = getIssuerStatus(ctx, issuerName)
			errorCondition = meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeError)
			Expect(errorCondition).To(BeNil())
		})
	})

	Context("when metadata discovery fails", func() {
		BeforeEach(func() {
			createIssuer(ctx, issuerName, vcv1alpha1.CredentialIssuerSpec{
				IssuerURL:     issuerURL,
				AuthSecretRef: vcv1alpha1.SecretReference{Name: secretName},
			})
			createSecret(ctx, secretName, map[string][]byte{
				AuthSecretKeyClientID:     []byte("my-client-id"),
				AuthSecretKeyClientSecret: []byte("my-client-secret"),
			})
			mockClient.discoverMetadataFunc = func(_ context.Context, _ string) (*oid4vci.IssuerMetadata, error) {
				return nil, fmt.Errorf("connection refused")
			}
		})

		AfterEach(func() {
			deleteIssuer(ctx, issuerName)
			deleteSecret(ctx, secretName)
		})

		It("should set Ready=False with MetadataFetchFailed reason", func() {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).To(HaveOccurred())

			status := getIssuerStatus(ctx, issuerName)

			readyCondition := meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeReady)
			Expect(readyCondition).NotTo(BeNil())
			Expect(readyCondition.Status).To(Equal(metav1.ConditionFalse))
			Expect(readyCondition.Reason).To(Equal(vcv1alpha1.ReasonMetadataFetchFailed))

			errorCondition := meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeError)
			Expect(errorCondition).NotTo(BeNil())
			Expect(errorCondition.Status).To(Equal(metav1.ConditionTrue))
			Expect(errorCondition.Reason).To(Equal(vcv1alpha1.ReasonMetadataFetchFailed))
		})

		It("should return an error for exponential backoff", func() {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("connection refused"))
		})

		It("should record a warning event for metadata fetch failure", func() {
			_, _ = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})

			var event string
			Expect(eventRecorder.Events).Should(Receive(&event))
			Expect(event).To(ContainSubstring(vcv1alpha1.ReasonMetadataFetchFailed))
			Expect(event).To(ContainSubstring("connection refused"))
		})
	})

	Context("when spec.tokenURL overrides the discovered token endpoint", func() {
		const customTokenURL = "https://custom-token.example.com/oauth/token"

		BeforeEach(func() {
			createIssuer(ctx, issuerName, vcv1alpha1.CredentialIssuerSpec{
				IssuerURL:     issuerURL,
				AuthSecretRef: vcv1alpha1.SecretReference{Name: secretName},
				TokenURL:      customTokenURL,
			})
			createSecret(ctx, secretName, map[string][]byte{
				AuthSecretKeyClientID:     []byte("my-client-id"),
				AuthSecretKeyClientSecret: []byte("my-client-secret"),
			})
			mockClient.discoverMetadataFunc = func(_ context.Context, _ string) (*oid4vci.IssuerMetadata, error) {
				return defaultMetadata(), nil
			}
		})

		AfterEach(func() {
			deleteIssuer(ctx, issuerName)
			deleteSecret(ctx, secretName)
		})

		It("should use the spec.tokenURL instead of the discovered endpoint", func() {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			status := getIssuerStatus(ctx, issuerName)
			Expect(status.TokenEndpoint).To(Equal(customTokenURL))
			// Credential endpoint should still come from metadata.
			Expect(status.CredentialEndpoint).To(Equal("https://issuer.example.com/credentials"))
		})
	})

	Context("when metadata has no credential configurations", func() {
		BeforeEach(func() {
			createIssuer(ctx, issuerName, vcv1alpha1.CredentialIssuerSpec{
				IssuerURL:     issuerURL,
				AuthSecretRef: vcv1alpha1.SecretReference{Name: secretName},
			})
			createSecret(ctx, secretName, map[string][]byte{
				AuthSecretKeyClientID:     []byte("my-client-id"),
				AuthSecretKeyClientSecret: []byte("my-client-secret"),
			})
			mockClient.discoverMetadataFunc = func(_ context.Context, _ string) (*oid4vci.IssuerMetadata, error) {
				return &oid4vci.IssuerMetadata{
					CredentialIssuer:                  "https://issuer.example.com",
					CredentialEndpoint:                "https://issuer.example.com/credentials",
					TokenEndpoint:                     "https://issuer.example.com/token",
					CredentialConfigurationsSupported: map[string]oid4vci.CredentialConfiguration{},
				}, nil
			}
		})

		AfterEach(func() {
			deleteIssuer(ctx, issuerName)
			deleteSecret(ctx, secretName)
		})

		It("should still set Ready=True with empty supported types", func() {
			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(MetadataRefreshInterval))

			status := getIssuerStatus(ctx, issuerName)
			Expect(status.SupportedCredentialTypes).To(BeEmpty())

			readyCondition := meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeReady)
			Expect(readyCondition).NotTo(BeNil())
			Expect(readyCondition.Status).To(Equal(metav1.ConditionTrue))
		})
	})

	Context("when the issuer URL is passed correctly to the OID4VCI client", func() {
		const customIssuerURL = "https://keycloak.production.example.com/realms/my-realm"

		BeforeEach(func() {
			createIssuer(ctx, issuerName, vcv1alpha1.CredentialIssuerSpec{
				IssuerURL:     customIssuerURL,
				AuthSecretRef: vcv1alpha1.SecretReference{Name: secretName},
			})
			createSecret(ctx, secretName, map[string][]byte{
				AuthSecretKeyClientID:     []byte("my-client-id"),
				AuthSecretKeyClientSecret: []byte("my-client-secret"),
			})
		})

		AfterEach(func() {
			deleteIssuer(ctx, issuerName)
			deleteSecret(ctx, secretName)
		})

		It("should pass the exact issuer URL to DiscoverMetadata", func() {
			var capturedURL string
			mockClient.discoverMetadataFunc = func(_ context.Context, issuerURL string) (*oid4vci.IssuerMetadata, error) {
				capturedURL = issuerURL
				return defaultMetadata(), nil
			}

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(capturedURL).To(Equal(customIssuerURL))
		})
	})
})

var _ = Describe("hasSecretKey", func() {
	DescribeTable("checks data map for non-empty values",
		func(data map[string][]byte, key string, expected bool) {
			Expect(hasSecretKey(data, key)).To(Equal(expected))
		},
		Entry("key present with non-empty value", map[string][]byte{"key": []byte("value")}, "key", true),
		Entry("key present with empty value", map[string][]byte{"key": []byte("")}, "key", false),
		Entry("key not present", map[string][]byte{"other": []byte("value")}, "key", false),
		Entry("nil data map", nil, "key", false),
		Entry("empty data map", map[string][]byte{}, "key", false),
	)
})

var _ = Describe("extractSupportedTypes", func() {
	It("should return sorted credential type identifiers", func() {
		metadata := &oid4vci.IssuerMetadata{
			CredentialConfigurationsSupported: map[string]oid4vci.CredentialConfiguration{
				"Zebra":  {Format: "jwt_vc_json"},
				"Alpha":  {Format: "jwt_vc_json"},
				"Middle": {Format: "ldp_vc"},
			},
		}
		types := extractSupportedTypes(metadata)
		Expect(types).To(Equal([]string{"Alpha", "Middle", "Zebra"}))
	})

	It("should return empty slice for no configurations", func() {
		metadata := &oid4vci.IssuerMetadata{
			CredentialConfigurationsSupported: map[string]oid4vci.CredentialConfiguration{},
		}
		types := extractSupportedTypes(metadata)
		Expect(types).To(BeEmpty())
	})
})
