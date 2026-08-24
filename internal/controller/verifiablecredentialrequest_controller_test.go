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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	vcv1alpha1 "github.com/SEAMWARE/vc-operator/api/v1alpha1"
	"github.com/SEAMWARE/vc-operator/internal/credential"
	"github.com/SEAMWARE/vc-operator/internal/credentialstore"
	"github.com/SEAMWARE/vc-operator/internal/oid4vci"
)

// mockCredentialStore is a configurable mock implementation of
// credentialstore.CredentialStore for testing the VCRequest controller
// without depending on a real storage backend.
type mockCredentialStore struct {
	storeFunc    func(ctx context.Context, ref credentialstore.TargetRef, data *credentialstore.CredentialData) error
	retrieveFunc func(ctx context.Context, ref credentialstore.TargetRef) (*credentialstore.CredentialData, error)
	deleteFunc   func(ctx context.Context, ref credentialstore.TargetRef) error

	// storeCalls tracks the number of Store calls for assertion purposes.
	storeCalls int
	// lastStored captures the last CredentialData passed to Store.
	lastStored *credentialstore.CredentialData
	// lastRef captures the last TargetRef passed to Store.
	lastRef *credentialstore.TargetRef
	// stored holds the credential currently in the mock backend. It backs the
	// default Retrieve so that the mock behaves like a real store: what was
	// successfully stored can be read back. Setting it to nil simulates the
	// target Secret being deleted out-of-band.
	stored *credentialstore.CredentialData
}

// Store delegates to the configured mock function or succeeds by default. On
// success the data is retained so that a subsequent Retrieve returns it.
func (m *mockCredentialStore) Store(ctx context.Context, ref credentialstore.TargetRef, data *credentialstore.CredentialData) error {
	m.storeCalls++
	m.lastStored = data
	m.lastRef = &ref
	if m.storeFunc != nil {
		if err := m.storeFunc(ctx, ref, data); err != nil {
			return err
		}
	}
	m.stored = data
	return nil
}

// Retrieve delegates to the configured mock function, or returns whatever was
// last stored. An empty backend reports the sentinel the CredentialStore
// contract requires.
func (m *mockCredentialStore) Retrieve(ctx context.Context, ref credentialstore.TargetRef) (*credentialstore.CredentialData, error) {
	if m.retrieveFunc != nil {
		return m.retrieveFunc(ctx, ref)
	}
	if m.stored == nil {
		return nil, fmt.Errorf("mock store is empty: %w", credentialstore.ErrNotFound)
	}
	return m.stored, nil
}

// Delete delegates to the configured mock function or succeeds by default.
func (m *mockCredentialStore) Delete(ctx context.Context, ref credentialstore.TargetRef) error {
	if m.deleteFunc != nil {
		return m.deleteFunc(ctx, ref)
	}
	return nil
}

// buildTestJWT creates a compact-serialized JWT with the given claims for testing.
// It uses a dummy header and signature — only the payload is meaningful for parsing.
func buildTestJWT(claims map[string]any) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`))

	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signature := base64.RawURLEncoding.EncodeToString([]byte("test-signature"))

	return header + "." + payload + "." + signature
}

// buildTestJWTWithExpiry creates a JWT with iat and exp claims set relative to
// the reference time.
func buildTestJWTWithExpiry(iat time.Time, expiry time.Time) string {
	claims := map[string]any{
		"iat": float64(iat.Unix()),
		"exp": float64(expiry.Unix()),
		"sub": "test-subject",
		"iss": "https://issuer.example.com",
	}
	return buildTestJWT(claims)
}

// getCounterValue reads the current value of a Prometheus counter metric
// for the given label values.
func getCounterValue(counter *prometheus.CounterVec, labels ...string) float64 {
	m := &dto.Metric{}
	c, err := counter.GetMetricWithLabelValues(labels...)
	if err != nil {
		return 0
	}
	if err := c.(prometheus.Metric).Write(m); err != nil {
		return 0
	}
	if m.Counter == nil {
		return 0
	}
	return m.Counter.GetValue()
}

// getGaugeValue reads the current value of a Prometheus gauge metric
// for the given label values.
func getGaugeValue(gauge *prometheus.GaugeVec, labels ...string) float64 {
	m := &dto.Metric{}
	g, err := gauge.GetMetricWithLabelValues(labels...)
	if err != nil {
		return 0
	}
	if err := g.(prometheus.Metric).Write(m); err != nil {
		return 0
	}
	if m.Gauge == nil {
		return 0
	}
	return m.Gauge.GetValue()
}

var _ = Describe("VerifiableCredentialRequest Controller", func() {
	const (
		vcReqName      = "test-vcreq"
		vcReqNs        = "default"
		issuerName     = "test-vc-issuer"
		authSecretName = "test-vc-auth-secret"
		targetSecret   = "test-target-secret"
		credType       = "VerifiableCredential"
	)

	var (
		typeNamespacedName types.NamespacedName
		mockOID4VCI        *mockOID4VCIClient
		mockStore          *mockCredentialStore
		eventRecorder      *events.FakeRecorder
		reconciler         *VerifiableCredentialRequestReconciler
	)

	BeforeEach(func() {
		typeNamespacedName = types.NamespacedName{
			Name:      vcReqName,
			Namespace: vcReqNs,
		}
		mockOID4VCI = &mockOID4VCIClient{}
		mockStore = &mockCredentialStore{}
		eventRecorder = events.NewFakeRecorder(fakeEventBufferSize)
		reconciler = &VerifiableCredentialRequestReconciler{
			Client:          k8sClient,
			Scheme:          k8sClient.Scheme(),
			OID4VCIClient:   mockOID4VCI,
			CredentialStore: mockStore,
			EventRecorder:   eventRecorder,
		}
	})

	// createReadyIssuer creates a CredentialIssuer CR and sets its status to Ready
	// with populated endpoints.
	createReadyIssuer := func(ctx context.Context) {
		issuer := &vcv1alpha1.CredentialIssuer{
			ObjectMeta: metav1.ObjectMeta{
				Name:      issuerName,
				Namespace: vcReqNs,
			},
			Spec: vcv1alpha1.CredentialIssuerSpec{
				IssuerURL:     "https://issuer.example.com",
				AuthSecretRef: vcv1alpha1.SecretReference{Name: authSecretName},
			},
		}
		Expect(k8sClient.Create(ctx, issuer)).To(Succeed())

		// Update status with Ready condition and endpoints.
		Eventually(func() error {
			var fetched vcv1alpha1.CredentialIssuer
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: issuerName, Namespace: vcReqNs}, &fetched); err != nil {
				return err
			}
			fetched.Status.CredentialEndpoint = "https://issuer.example.com/credentials"
			fetched.Status.TokenEndpoint = "https://issuer.example.com/token"
			fetched.Status.SupportedCredentialTypes = []string{"VerifiableCredential"}
			meta.SetStatusCondition(&fetched.Status.Conditions, metav1.Condition{
				Type:               vcv1alpha1.ConditionTypeReady,
				Status:             metav1.ConditionTrue,
				Reason:             vcv1alpha1.ReasonMetadataDiscovered,
				Message:            "Issuer is ready",
				ObservedGeneration: fetched.Generation,
			})
			return k8sClient.Status().Update(ctx, &fetched)
		}).Should(Succeed())
	}

	// createNotReadyIssuer creates a CredentialIssuer CR without a Ready condition.
	createNotReadyIssuer := func(ctx context.Context) {
		issuer := &vcv1alpha1.CredentialIssuer{
			ObjectMeta: metav1.ObjectMeta{
				Name:      issuerName,
				Namespace: vcReqNs,
			},
			Spec: vcv1alpha1.CredentialIssuerSpec{
				IssuerURL:     "https://issuer.example.com",
				AuthSecretRef: vcv1alpha1.SecretReference{Name: authSecretName},
			},
		}
		Expect(k8sClient.Create(ctx, issuer)).To(Succeed())
	}

	// createAuthSecret creates an auth Secret with client_credentials keys.
	createAuthSecret := func(ctx context.Context) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      authSecretName,
				Namespace: vcReqNs,
			},
			Data: map[string][]byte{
				AuthSecretKeyClientID:     []byte("test-client-id"),
				AuthSecretKeyClientSecret: []byte("test-client-secret"),
			},
		}
		Expect(k8sClient.Create(ctx, secret)).To(Succeed())
	}

	// createVCRequest creates a VerifiableCredentialRequest CR.
	createVCRequest := func(ctx context.Context) {
		vcReq := &vcv1alpha1.VerifiableCredentialRequest{
			ObjectMeta: metav1.ObjectMeta{
				Name:      vcReqName,
				Namespace: vcReqNs,
			},
			Spec: vcv1alpha1.VerifiableCredentialRequestSpec{
				IssuerRef:      vcv1alpha1.LocalObjectReference{Name: issuerName},
				CredentialType: credType,
				Format:         "jwt_vc_json",
				TargetSecretRef: vcv1alpha1.TargetSecretReference{
					Name: targetSecret,
					Key:  "credential",
				},
			},
		}
		Expect(k8sClient.Create(ctx, vcReq)).To(Succeed())
	}

	// deleteResource deletes a resource if it exists, ignoring not-found errors.
	deleteResource := func(ctx context.Context, obj client.Object, name string) {
		key := types.NamespacedName{Name: name, Namespace: vcReqNs}
		if err := k8sClient.Get(ctx, key, obj); err == nil {
			_ = k8sClient.Delete(ctx, obj)
		}
	}

	// getVCRequestStatus fetches the current VCRequest and returns its status.
	getVCRequestStatus := func(ctx context.Context) vcv1alpha1.VerifiableCredentialRequestStatus {
		var vcReq vcv1alpha1.VerifiableCredentialRequest
		key := types.NamespacedName{Name: vcReqName, Namespace: vcReqNs}
		Expect(k8sClient.Get(ctx, key, &vcReq)).To(Succeed())
		return vcReq.Status
	}

	// setupCredentialOfferMocks configures the credential offer mock functions
	// needed for the client_credentials → pre-authorized code flow.
	setupCredentialOfferMocks := func() {
		mockOID4VCI.createCredentialOfferFunc = func(_ context.Context, _, _, _ string) (*oid4vci.CredentialOfferURI, error) {
			return &oid4vci.CredentialOfferURI{
				Issuer: "https://issuer.example.com/protocol/oid4vc/credential-offer",
				Nonce:  "test-nonce-123",
			}, nil
		}
		mockOID4VCI.fetchCredentialOfferFunc = func(_ context.Context, _, _ string) (*oid4vci.CredentialOffer, error) {
			return &oid4vci.CredentialOffer{
				CredentialIssuer:           "https://issuer.example.com",
				CredentialConfigurationIDs: []string{credType},
				Grants: map[string]oid4vci.PreAuthorizedGrant{
					string(oid4vci.GrantTypePreAuthorizedCode): {
						Code: "test-pre-auth-code",
					},
				},
			}, nil
		}
	}

	// preAuthTokenResponse returns a TokenResponse with authorization_details
	// matching what Keycloak's pre-authorized code grant produces.
	preAuthTokenResponse := func(expiresIn int) *oid4vci.TokenResponse {
		return &oid4vci.TokenResponse{
			AccessToken: "test-access-token",
			TokenType:   "Bearer",
			ExpiresIn:   expiresIn,
			AuthorizationDetails: []oid4vci.AuthorizationDetail{
				{
					Type:                      "openid_credential",
					CredentialConfigurationID: credType,
					CredentialIdentifiers:     []string{credType + "_0000"},
				},
			},
		}
	}

	// setupHappyPath configures mocks for a successful credential issuance flow.
	setupHappyPath := func() {
		now := time.Now()
		expiry := now.Add(1 * time.Hour)
		testJWT := buildTestJWTWithExpiry(now, expiry)

		setupCredentialOfferMocks()
		mockOID4VCI.obtainAccessTokenFunc = func(_ context.Context, _ string, auth oid4vci.TokenAuth) (*oid4vci.TokenResponse, error) {
			if auth.GrantType == oid4vci.GrantTypePreAuthorizedCode {
				return preAuthTokenResponse(3600), nil
			}
			return &oid4vci.TokenResponse{
				AccessToken: "test-admin-token",
				TokenType:   "Bearer",
				ExpiresIn:   3600,
			}, nil
		}
		mockOID4VCI.requestCredentialFunc = func(_ context.Context, _ string, _ string, _ oid4vci.CredentialRequest) (*oid4vci.CredentialResponse, error) {
			return &oid4vci.CredentialResponse{
				Credential: testJWT,
				Format:     "jwt_vc_json",
			}, nil
		}
	}

	// setupHappyPathWithClock configures mocks that use a specific reference time
	// for generating JWTs, enabling deterministic time-based testing.
	setupHappyPathWithClock := func(refTime time.Time, credDuration time.Duration) {
		expiry := refTime.Add(credDuration)
		testJWT := buildTestJWTWithExpiry(refTime, expiry)

		setupCredentialOfferMocks()
		mockOID4VCI.obtainAccessTokenFunc = func(_ context.Context, _ string, auth oid4vci.TokenAuth) (*oid4vci.TokenResponse, error) {
			if auth.GrantType == oid4vci.GrantTypePreAuthorizedCode {
				return preAuthTokenResponse(int(credDuration.Seconds())), nil
			}
			return &oid4vci.TokenResponse{
				AccessToken: "test-admin-token",
				TokenType:   "Bearer",
				ExpiresIn:   int(credDuration.Seconds()),
			}, nil
		}
		mockOID4VCI.requestCredentialFunc = func(_ context.Context, _ string, _ string, _ oid4vci.CredentialRequest) (*oid4vci.CredentialResponse, error) {
			return &oid4vci.CredentialResponse{
				Credential: testJWT,
				Format:     "jwt_vc_json",
			}, nil
		}
	}

	Context("when the VerifiableCredentialRequest resource is not found", func() {
		It("should return without error and not requeue", func() {
			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      "nonexistent",
					Namespace: vcReqNs,
				},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ctrl.Result{}))
		})
	})

	Context("when the referenced CredentialIssuer does not exist", func() {
		BeforeEach(func() {
			createVCRequest(ctx)
		})

		AfterEach(func() {
			deleteResource(ctx, &vcv1alpha1.VerifiableCredentialRequest{}, vcReqName)
		})

		It("should set Ready=False with IssuerNotFound reason", func() {
			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(IssuerNotReadyRequeueInterval))

			status := getVCRequestStatus(ctx)
			readyCondition := meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeReady)
			Expect(readyCondition).NotTo(BeNil())
			Expect(readyCondition.Status).To(Equal(metav1.ConditionFalse))
			Expect(readyCondition.Reason).To(Equal(vcv1alpha1.ReasonIssuerNotFound))

			errorCondition := meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeError)
			Expect(errorCondition).NotTo(BeNil())
			Expect(errorCondition.Status).To(Equal(metav1.ConditionTrue))
		})

		It("should record a warning event for the missing issuer", func() {
			_, _ = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})

			var event string
			Expect(eventRecorder.Events).Should(Receive(&event))
			Expect(event).To(ContainSubstring(vcv1alpha1.ReasonIssuerNotFound))
		})
	})

	Context("when the referenced CredentialIssuer is not Ready", func() {
		BeforeEach(func() {
			createNotReadyIssuer(ctx)
			createVCRequest(ctx)
		})

		AfterEach(func() {
			deleteResource(ctx, &vcv1alpha1.VerifiableCredentialRequest{}, vcReqName)
			deleteResource(ctx, &vcv1alpha1.CredentialIssuer{}, issuerName)
		})

		It("should set Ready=False with IssuerNotReady reason", func() {
			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(IssuerNotReadyRequeueInterval))

			status := getVCRequestStatus(ctx)
			readyCondition := meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeReady)
			Expect(readyCondition).NotTo(BeNil())
			Expect(readyCondition.Status).To(Equal(metav1.ConditionFalse))
			Expect(readyCondition.Reason).To(Equal(vcv1alpha1.ReasonIssuerNotReady))
		})

		It("should record a warning event for the not-ready issuer", func() {
			_, _ = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})

			var event string
			Expect(eventRecorder.Events).Should(Receive(&event))
			Expect(event).To(ContainSubstring(vcv1alpha1.ReasonIssuerNotReady))
		})
	})

	Context("when the auth Secret is not found", func() {
		BeforeEach(func() {
			createReadyIssuer(ctx)
			createVCRequest(ctx)
			// Do NOT create the auth secret.
		})

		AfterEach(func() {
			deleteResource(ctx, &vcv1alpha1.VerifiableCredentialRequest{}, vcReqName)
			deleteResource(ctx, &vcv1alpha1.CredentialIssuer{}, issuerName)
		})

		It("should set Ready=False with AuthSecretNotFound reason", func() {
			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(DefaultConfigErrorRequeueInterval))

			status := getVCRequestStatus(ctx)
			readyCondition := meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeReady)
			Expect(readyCondition).NotTo(BeNil())
			Expect(readyCondition.Status).To(Equal(metav1.ConditionFalse))
			Expect(readyCondition.Reason).To(Equal(vcv1alpha1.ReasonAuthSecretNotFound))
		})
	})

	Context("when the token request fails", func() {
		BeforeEach(func() {
			createReadyIssuer(ctx)
			createAuthSecret(ctx)
			createVCRequest(ctx)
			mockOID4VCI.obtainAccessTokenFunc = func(_ context.Context, _ string, _ oid4vci.TokenAuth) (*oid4vci.TokenResponse, error) {
				return nil, fmt.Errorf("token endpoint unreachable")
			}
		})

		AfterEach(func() {
			deleteResource(ctx, &vcv1alpha1.VerifiableCredentialRequest{}, vcReqName)
			deleteResource(ctx, &vcv1alpha1.CredentialIssuer{}, issuerName)
			deleteResource(ctx, &corev1.Secret{}, authSecretName)
		})

		It("should set Error condition with CredentialRequestFailed reason and return error for backoff", func() {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("token endpoint unreachable"))

			status := getVCRequestStatus(ctx)
			errorCondition := meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeError)
			Expect(errorCondition).NotTo(BeNil())
			Expect(errorCondition.Status).To(Equal(metav1.ConditionTrue))
			Expect(errorCondition.Reason).To(Equal(vcv1alpha1.ReasonCredentialRequestFailed))
		})

		It("should record a warning event for the token failure", func() {
			_, _ = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})

			var event string
			Expect(eventRecorder.Events).Should(Receive(&event))
			Expect(event).To(ContainSubstring(vcv1alpha1.ReasonCredentialRequestFailed))
		})
	})

	Context("when the credential request fails", func() {
		BeforeEach(func() {
			createReadyIssuer(ctx)
			createAuthSecret(ctx)
			createVCRequest(ctx)
			setupCredentialOfferMocks()
			mockOID4VCI.obtainAccessTokenFunc = func(_ context.Context, _ string, _ oid4vci.TokenAuth) (*oid4vci.TokenResponse, error) {
				return &oid4vci.TokenResponse{
					AccessToken: "test-access-token",
					TokenType:   "Bearer",
				}, nil
			}
			mockOID4VCI.requestCredentialFunc = func(_ context.Context, _ string, _ string, _ oid4vci.CredentialRequest) (*oid4vci.CredentialResponse, error) {
				return nil, fmt.Errorf("credential endpoint error")
			}
		})

		AfterEach(func() {
			deleteResource(ctx, &vcv1alpha1.VerifiableCredentialRequest{}, vcReqName)
			deleteResource(ctx, &vcv1alpha1.CredentialIssuer{}, issuerName)
			deleteResource(ctx, &corev1.Secret{}, authSecretName)
		})

		It("should set Error condition with CredentialRequestFailed reason", func() {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("credential endpoint error"))

			status := getVCRequestStatus(ctx)
			errorCondition := meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeError)
			Expect(errorCondition).NotTo(BeNil())
			Expect(errorCondition.Reason).To(Equal(vcv1alpha1.ReasonCredentialRequestFailed))
		})
	})

	Context("when credential storage fails", func() {
		BeforeEach(func() {
			createReadyIssuer(ctx)
			createAuthSecret(ctx)
			createVCRequest(ctx)

			now := time.Now()
			expiry := now.Add(1 * time.Hour)
			testJWT := buildTestJWTWithExpiry(now, expiry)

			setupCredentialOfferMocks()
			mockOID4VCI.obtainAccessTokenFunc = func(_ context.Context, _ string, _ oid4vci.TokenAuth) (*oid4vci.TokenResponse, error) {
				return &oid4vci.TokenResponse{AccessToken: "token", TokenType: "Bearer"}, nil
			}
			mockOID4VCI.requestCredentialFunc = func(_ context.Context, _ string, _ string, _ oid4vci.CredentialRequest) (*oid4vci.CredentialResponse, error) {
				return &oid4vci.CredentialResponse{Credential: testJWT, Format: "jwt_vc_json"}, nil
			}
			mockStore.storeFunc = func(_ context.Context, _ credentialstore.TargetRef, _ *credentialstore.CredentialData) error {
				return fmt.Errorf("storage backend unavailable")
			}
		})

		AfterEach(func() {
			deleteResource(ctx, &vcv1alpha1.VerifiableCredentialRequest{}, vcReqName)
			deleteResource(ctx, &vcv1alpha1.CredentialIssuer{}, issuerName)
			deleteResource(ctx, &corev1.Secret{}, authSecretName)
		})

		It("should set Error condition with StorageFailed reason and return error for backoff", func() {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("storage backend unavailable"))

			status := getVCRequestStatus(ctx)
			errorCondition := meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeError)
			Expect(errorCondition).NotTo(BeNil())
			Expect(errorCondition.Reason).To(Equal(vcv1alpha1.ReasonStorageFailed))
		})
	})

	Context("when the credential response is not a string", func() {
		BeforeEach(func() {
			createReadyIssuer(ctx)
			createAuthSecret(ctx)
			createVCRequest(ctx)

			setupCredentialOfferMocks()
			mockOID4VCI.obtainAccessTokenFunc = func(_ context.Context, _ string, _ oid4vci.TokenAuth) (*oid4vci.TokenResponse, error) {
				return &oid4vci.TokenResponse{AccessToken: "token", TokenType: "Bearer"}, nil
			}
			mockOID4VCI.requestCredentialFunc = func(_ context.Context, _ string, _ string, _ oid4vci.CredentialRequest) (*oid4vci.CredentialResponse, error) {
				// Return a non-string credential (JSON-LD format).
				return &oid4vci.CredentialResponse{
					Credential: map[string]any{"@context": "test"},
					Format:     "ldp_vc",
				}, nil
			}
		})

		AfterEach(func() {
			deleteResource(ctx, &vcv1alpha1.VerifiableCredentialRequest{}, vcReqName)
			deleteResource(ctx, &vcv1alpha1.CredentialIssuer{}, issuerName)
			deleteResource(ctx, &corev1.Secret{}, authSecretName)
		})

		It("should set Error condition for non-string credential response", func() {
			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(DefaultConfigErrorRequeueInterval))

			status := getVCRequestStatus(ctx)
			errorCondition := meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeError)
			Expect(errorCondition).NotTo(BeNil())
			Expect(errorCondition.Reason).To(Equal(vcv1alpha1.ReasonCredentialRequestFailed))
			Expect(errorCondition.Message).To(ContainSubstring("did not contain a string credential"))
		})
	})

	Context("happy path: full credential issuance flow", func() {
		BeforeEach(func() {
			createReadyIssuer(ctx)
			createAuthSecret(ctx)
			createVCRequest(ctx)
			setupHappyPath()
		})

		AfterEach(func() {
			deleteResource(ctx, &vcv1alpha1.VerifiableCredentialRequest{}, vcReqName)
			deleteResource(ctx, &vcv1alpha1.CredentialIssuer{}, issuerName)
			deleteResource(ctx, &corev1.Secret{}, authSecretName)
		})

		It("should set Ready=True and CredentialIssued=True conditions", func() {
			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(BeNumerically(">", 0))

			status := getVCRequestStatus(ctx)

			readyCondition := meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeReady)
			Expect(readyCondition).NotTo(BeNil())
			Expect(readyCondition.Status).To(Equal(metav1.ConditionTrue))
			Expect(readyCondition.Reason).To(Equal(vcv1alpha1.ReasonCredentialObtained))

			issuedCondition := meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeCredentialIssued)
			Expect(issuedCondition).NotTo(BeNil())
			Expect(issuedCondition.Status).To(Equal(metav1.ConditionTrue))
			Expect(issuedCondition.Reason).To(Equal(vcv1alpha1.ReasonCredentialObtained))
		})

		It("should set RenewalScheduled condition", func() {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			status := getVCRequestStatus(ctx)
			renewalCondition := meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeRenewalScheduled)
			Expect(renewalCondition).NotTo(BeNil())
			Expect(renewalCondition.Status).To(Equal(metav1.ConditionTrue))
			Expect(renewalCondition.Reason).To(Equal(vcv1alpha1.ReasonRenewalScheduled))
		})

		It("should clear Error condition on success", func() {
			// First, induce an error condition.
			failStore := &mockCredentialStore{
				storeFunc: func(_ context.Context, _ credentialstore.TargetRef, _ *credentialstore.CredentialData) error {
					return fmt.Errorf("transient failure")
				},
			}
			failReconciler := &VerifiableCredentialRequestReconciler{
				Client:          k8sClient,
				Scheme:          k8sClient.Scheme(),
				OID4VCIClient:   mockOID4VCI,
				CredentialStore: failStore,
				EventRecorder:   events.NewFakeRecorder(fakeEventBufferSize),
			}
			_, _ = failReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})

			// Verify Error condition was set.
			status := getVCRequestStatus(ctx)
			errorCondition := meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeError)
			Expect(errorCondition).NotTo(BeNil())

			// Now succeed — Error should be cleared.
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			status = getVCRequestStatus(ctx)
			errorCondition = meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeError)
			Expect(errorCondition).To(BeNil())
		})

		It("should populate status timestamps", func() {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			status := getVCRequestStatus(ctx)
			Expect(status.LastIssuanceTime).NotTo(BeNil())
			Expect(status.NextRenewalTime).NotTo(BeNil())
			Expect(status.CredentialExpiryTime).NotTo(BeNil())
			Expect(status.CredentialFormat).To(Equal("jwt_vc_json"))
		})

		It("should store the credential via the CredentialStore", func() {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(mockStore.storeCalls).To(Equal(1))
			Expect(mockStore.lastStored).NotTo(BeNil())
			Expect(mockStore.lastStored.Format).To(Equal("jwt_vc_json"))
			Expect(mockStore.lastStored.Credential).ToNot(BeEmpty())
		})

		It("should set correct TargetRef with owner information", func() {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(mockStore.lastRef).NotTo(BeNil())
			Expect(mockStore.lastRef.Namespace).To(Equal(vcReqNs))
			Expect(mockStore.lastRef.Name).To(Equal(targetSecret))
			Expect(mockStore.lastRef.Key).To(Equal("credential"))
			Expect(mockStore.lastRef.OwnerName).To(Equal(vcReqName))
			Expect(mockStore.lastRef.OwnerGVK.Kind).To(Equal("VerifiableCredentialRequest"))
		})

		It("should record a success event", func() {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			var event string
			Expect(eventRecorder.Events).Should(Receive(&event))
			Expect(event).To(ContainSubstring(vcv1alpha1.ReasonCredentialObtained))
			Expect(event).To(ContainSubstring(credType))
		})

		It("should requeue before credential expiry", func() {
			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			// The JWT expires in 1 hour and renewBefore defaults to 5 minutes,
			// so requeue should be approximately 55 minutes (with tolerance).
			Expect(result.RequeueAfter).To(BeNumerically(">", 50*time.Minute))
			Expect(result.RequeueAfter).To(BeNumerically("<", 60*time.Minute))
		})
	})

	Context("happy path: credential renewal (second issuance)", func() {
		var fakeClock *FakeClock

		BeforeEach(func() {
			createReadyIssuer(ctx)
			createAuthSecret(ctx)
			createVCRequest(ctx)

			fakeClock = &FakeClock{
				CurrentTime: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC),
			}
			reconciler.Clock = fakeClock
			setupHappyPathWithClock(fakeClock.CurrentTime, 1*time.Hour)
		})

		AfterEach(func() {
			deleteResource(ctx, &vcv1alpha1.VerifiableCredentialRequest{}, vcReqName)
			deleteResource(ctx, &vcv1alpha1.CredentialIssuer{}, issuerName)
			deleteResource(ctx, &corev1.Secret{}, authSecretName)
		})

		It("should set LastRenewalTime on second reconciliation", func() {
			// First reconciliation — initial issuance.
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			status := getVCRequestStatus(ctx)
			Expect(status.LastIssuanceTime).NotTo(BeNil())
			// First issuance should NOT set LastRenewalTime.
			Expect(status.LastRenewalTime).To(BeNil())

			// Advance clock past the renewal time (expiry 13:00, renewBefore 5m → renewal at 12:55).
			fakeClock.SetTime(time.Date(2026, 6, 1, 12, 56, 0, 0, time.UTC))
			setupHappyPathWithClock(fakeClock.CurrentTime, 1*time.Hour)

			// Second reconciliation — renewal.
			_, err = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			status = getVCRequestStatus(ctx)
			// Renewal should set LastRenewalTime.
			Expect(status.LastRenewalTime).NotTo(BeNil())
		})

		It("should record a renewal event on second issuance", func() {
			// First reconciliation.
			_, _ = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			// Drain first event.
			var event string
			Expect(eventRecorder.Events).Should(Receive(&event))

			// Advance clock past the renewal time.
			fakeClock.SetTime(time.Date(2026, 6, 1, 12, 56, 0, 0, time.UTC))
			setupHappyPathWithClock(fakeClock.CurrentTime, 1*time.Hour)

			// Second reconciliation — renewal.
			_, _ = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(eventRecorder.Events).Should(Receive(&event))
			Expect(event).To(ContainSubstring("Renewed"))
		})

		It("should increment RenewalCount on each renewal", func() {
			// First reconciliation — initial issuance.
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			status := getVCRequestStatus(ctx)
			Expect(status.RenewalCount).To(Equal(int32(0)))

			// Advance clock past the renewal time for first renewal.
			fakeClock.SetTime(time.Date(2026, 6, 1, 12, 56, 0, 0, time.UTC))
			setupHappyPathWithClock(fakeClock.CurrentTime, 1*time.Hour)

			// Second reconciliation — first renewal.
			_, err = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			status = getVCRequestStatus(ctx)
			Expect(status.RenewalCount).To(Equal(int32(1)))

			// Advance clock past the renewal time for second renewal.
			fakeClock.SetTime(time.Date(2026, 6, 1, 13, 52, 0, 0, time.UTC))
			setupHappyPathWithClock(fakeClock.CurrentTime, 1*time.Hour)

			// Third reconciliation — second renewal.
			_, err = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			status = getVCRequestStatus(ctx)
			Expect(status.RenewalCount).To(Equal(int32(2)))
		})
	})

	Context("stored credential missing: self-healing re-issuance", func() {
		var fakeClock *FakeClock
		var testMetrics *VCRequestMetrics

		BeforeEach(func() {
			createReadyIssuer(ctx)
			createAuthSecret(ctx)
			createVCRequest(ctx)

			fakeClock = &FakeClock{
				CurrentTime: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC),
			}
			reconciler.Clock = fakeClock
			setupHappyPathWithClock(fakeClock.CurrentTime, 1*time.Hour)

			testMetrics = NewVCRequestMetrics()
			reconciler.Metrics = testMetrics
		})

		AfterEach(func() {
			deleteResource(ctx, &vcv1alpha1.VerifiableCredentialRequest{}, vcReqName)
			deleteResource(ctx, &vcv1alpha1.CredentialIssuer{}, issuerName)
			deleteResource(ctx, &corev1.Secret{}, authSecretName)
		})

		// reconcileOnce runs a single reconciliation and asserts it succeeded.
		reconcileOnce := func() ctrl.Result {
			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			return result
		}

		It("should skip reconciliation while the stored credential is present", func() {
			reconcileOnce()
			Expect(mockStore.storeCalls).To(Equal(1))

			// The clock is deliberately not advanced: renewal is ~55 minutes
			// away, so a present credential must short-circuit the reconcile.
			result := reconcileOnce()
			Expect(mockStore.storeCalls).To(Equal(1))
			Expect(result.RequeueAfter).To(BeNumerically(">", 0))
		})

		It("should re-issue when the stored credential is gone", func() {
			reconcileOnce()
			Expect(mockStore.storeCalls).To(Equal(1))

			// Simulate the target Secret being deleted out-of-band.
			mockStore.stored = nil

			reconcileOnce()
			Expect(mockStore.storeCalls).To(Equal(2))
		})

		It("should re-issue when the stored credential is empty", func() {
			reconcileOnce()
			Expect(mockStore.storeCalls).To(Equal(1))

			// Simulate the credential key being emptied out-of-band.
			mockStore.stored = &credentialstore.CredentialData{Credential: nil}

			reconcileOnce()
			Expect(mockStore.storeCalls).To(Equal(2))
		})

		It("should keep skipping when the store returns a transient error", func() {
			reconcileOnce()
			Expect(mockStore.storeCalls).To(Equal(1))

			// A backend failure must not be mistaken for a missing credential:
			// a successful reconcile resets the workqueue rate limiter, so
			// re-issuing here would let a flaky backend hammer the issuer.
			mockStore.retrieveFunc = func(_ context.Context, _ credentialstore.TargetRef) (*credentialstore.CredentialData, error) {
				return nil, fmt.Errorf("apiserver unavailable")
			}

			reconcileOnce()
			Expect(mockStore.storeCalls).To(Equal(1))
		})

		It("should emit a warning event when the stored credential is missing", func() {
			reconcileOnce()

			// Drain the initial issuance event.
			var event string
			Expect(eventRecorder.Events).Should(Receive(&event))

			mockStore.stored = nil
			reconcileOnce()

			Expect(eventRecorder.Events).Should(Receive(&event))
			Expect(event).To(ContainSubstring(vcv1alpha1.ReasonStoredCredentialMissing))
		})

		It("should not emit a missing-credential event on the initial issuance", func() {
			reconcileOnce()

			var event string
			Expect(eventRecorder.Events).Should(Receive(&event))
			Expect(event).NotTo(ContainSubstring(vcv1alpha1.ReasonStoredCredentialMissing))
		})

		It("should count the restore as a renewal", func() {
			reconcileOnce()

			status := getVCRequestStatus(ctx)
			Expect(status.RenewalCount).To(Equal(int32(0)))
			Expect(status.LastRenewalTime).To(BeNil())

			mockStore.stored = nil
			reconcileOnce()

			// A restore reuses the renewal accounting path by design: it is
			// recorded as a renewal in both the status and the metrics.
			status = getVCRequestStatus(ctx)
			Expect(status.RenewalCount).To(Equal(int32(1)))
			Expect(status.LastRenewalTime).NotTo(BeNil())

			renewed := getCounterValue(testMetrics.CredentialsRenewedTotal, vcReqNs, vcReqName, credType)
			Expect(renewed).To(Equal(float64(1)))
		})
	})

	Context("happy path: previous credential rotation", func() {
		BeforeEach(func() {
			createReadyIssuer(ctx)
			createAuthSecret(ctx)
			createVCRequest(ctx)
			setupHappyPath()

			// Mock the retrieve to return an existing credential for rotation.
			mockStore.retrieveFunc = func(_ context.Context, _ credentialstore.TargetRef) (*credentialstore.CredentialData, error) {
				return &credentialstore.CredentialData{
					Credential: []byte("previous-jwt-credential"),
					Format:     "jwt_vc_json",
				}, nil
			}
		})

		AfterEach(func() {
			deleteResource(ctx, &vcv1alpha1.VerifiableCredentialRequest{}, vcReqName)
			deleteResource(ctx, &vcv1alpha1.CredentialIssuer{}, issuerName)
			deleteResource(ctx, &corev1.Secret{}, authSecretName)
		})

		It("should preserve the previous credential in the rotation buffer", func() {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(mockStore.lastStored).NotTo(BeNil())
			Expect(mockStore.lastStored.PreviousCredential).To(Equal([]byte("previous-jwt-credential")))
		})
	})

	Context("happy path: credential without expiry", func() {
		BeforeEach(func() {
			createReadyIssuer(ctx)
			createAuthSecret(ctx)
			createVCRequest(ctx)

			// Build a JWT without an exp claim.
			jwtWithoutExp := buildTestJWT(map[string]any{
				"iat": float64(time.Now().Unix()),
				"sub": "test-subject",
			})

			setupCredentialOfferMocks()
			mockOID4VCI.obtainAccessTokenFunc = func(_ context.Context, _ string, _ oid4vci.TokenAuth) (*oid4vci.TokenResponse, error) {
				return &oid4vci.TokenResponse{AccessToken: "token", TokenType: "Bearer"}, nil
			}
			mockOID4VCI.requestCredentialFunc = func(_ context.Context, _ string, _ string, _ oid4vci.CredentialRequest) (*oid4vci.CredentialResponse, error) {
				return &oid4vci.CredentialResponse{Credential: jwtWithoutExp, Format: "jwt_vc_json"}, nil
			}
		})

		AfterEach(func() {
			deleteResource(ctx, &vcv1alpha1.VerifiableCredentialRequest{}, vcReqName)
			deleteResource(ctx, &vcv1alpha1.CredentialIssuer{}, issuerName)
			deleteResource(ctx, &corev1.Secret{}, authSecretName)
		})

		It("should still succeed and schedule renewal using default TTL", func() {
			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(BeNumerically(">", 0))

			status := getVCRequestStatus(ctx)
			readyCondition := meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeReady)
			Expect(readyCondition).NotTo(BeNil())
			Expect(readyCondition.Status).To(Equal(metav1.ConditionTrue))

			// No explicit expiry, so CredentialExpiryTime should be nil.
			Expect(status.CredentialExpiryTime).To(BeNil())

			// But NextRenewalTime should still be set (using default TTL).
			Expect(status.NextRenewalTime).NotTo(BeNil())
		})
	})

	Context("token auth: pre-authorized code flow", func() {
		BeforeEach(func() {
			createReadyIssuer(ctx)
			createVCRequest(ctx)

			// Create auth secret with pre-authorized code.
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      authSecretName,
					Namespace: vcReqNs,
				},
				Data: map[string][]byte{
					AuthSecretKeyPreAuthorizedCode: []byte("pre-auth-code-123"),
				},
			}
			Expect(k8sClient.Create(ctx, secret)).To(Succeed())

			setupHappyPath()
		})

		AfterEach(func() {
			deleteResource(ctx, &vcv1alpha1.VerifiableCredentialRequest{}, vcReqName)
			deleteResource(ctx, &vcv1alpha1.CredentialIssuer{}, issuerName)
			deleteResource(ctx, &corev1.Secret{}, authSecretName)
		})

		It("should use pre-authorized code grant type", func() {
			var capturedAuth oid4vci.TokenAuth
			mockOID4VCI.obtainAccessTokenFunc = func(_ context.Context, _ string, auth oid4vci.TokenAuth) (*oid4vci.TokenResponse, error) {
				capturedAuth = auth
				return &oid4vci.TokenResponse{AccessToken: "token", TokenType: "Bearer"}, nil
			}

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(capturedAuth.GrantType).To(Equal(oid4vci.GrantTypePreAuthorizedCode))
			Expect(capturedAuth.PreAuthorizedCode).To(Equal("pre-auth-code-123"))
		})
	})

	Context("token auth: client credentials flow", func() {
		BeforeEach(func() {
			createReadyIssuer(ctx)
			createAuthSecret(ctx)
			createVCRequest(ctx)
			setupHappyPath()
		})

		AfterEach(func() {
			deleteResource(ctx, &vcv1alpha1.VerifiableCredentialRequest{}, vcReqName)
			deleteResource(ctx, &vcv1alpha1.CredentialIssuer{}, issuerName)
			deleteResource(ctx, &corev1.Secret{}, authSecretName)
		})

		It("should use client credentials for admin token, then pre-authorized code for credential token", func() {
			var capturedAuths []oid4vci.TokenAuth
			mockOID4VCI.obtainAccessTokenFunc = func(_ context.Context, _ string, auth oid4vci.TokenAuth) (*oid4vci.TokenResponse, error) {
				capturedAuths = append(capturedAuths, auth)
				if auth.GrantType == oid4vci.GrantTypePreAuthorizedCode {
					return preAuthTokenResponse(3600), nil
				}
				return &oid4vci.TokenResponse{AccessToken: "admin-token", TokenType: "Bearer"}, nil
			}

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(capturedAuths).To(HaveLen(2))
			Expect(capturedAuths[0].GrantType).To(Equal(oid4vci.GrantTypeClientCredentials))
			Expect(capturedAuths[0].ClientID).To(Equal("test-client-id"))
			Expect(capturedAuths[0].ClientSecret).To(Equal("test-client-secret"))
			Expect(capturedAuths[1].GrantType).To(Equal(oid4vci.GrantTypePreAuthorizedCode))
			Expect(capturedAuths[1].PreAuthorizedCode).To(Equal("test-pre-auth-code"))
		})
	})

	Context("credential request parameters", func() {
		BeforeEach(func() {
			createReadyIssuer(ctx)
			createAuthSecret(ctx)
			createVCRequest(ctx)
			setupHappyPath()
		})

		AfterEach(func() {
			deleteResource(ctx, &vcv1alpha1.VerifiableCredentialRequest{}, vcReqName)
			deleteResource(ctx, &vcv1alpha1.CredentialIssuer{}, issuerName)
			deleteResource(ctx, &corev1.Secret{}, authSecretName)
		})

		It("should use credential_identifier from authorization_details when available", func() {
			var capturedReq oid4vci.CredentialRequest
			var capturedURL string
			var capturedToken string

			mockOID4VCI.requestCredentialFunc = func(_ context.Context, credURL string, accessToken string, req oid4vci.CredentialRequest) (*oid4vci.CredentialResponse, error) {
				capturedReq = req
				capturedURL = credURL
				capturedToken = accessToken

				now := time.Now()
				expiry := now.Add(1 * time.Hour)
				return &oid4vci.CredentialResponse{
					Credential: buildTestJWTWithExpiry(now, expiry),
					Format:     "jwt_vc_json",
				}, nil
			}

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(capturedReq.CredentialIdentifier).To(Equal(credType + "_0000"))
			Expect(capturedReq.CredentialConfigurationID).To(BeEmpty())
			Expect(capturedReq.Format).To(BeEmpty())
			Expect(capturedURL).To(Equal("https://issuer.example.com/credentials"))
			Expect(capturedToken).To(Equal("test-access-token"))
		})
	})

	Context("custom renewBefore duration", func() {
		BeforeEach(func() {
			createReadyIssuer(ctx)
			createAuthSecret(ctx)

			// Create VCRequest with custom renewBefore = 30 minutes.
			renewBefore := metav1.Duration{Duration: 30 * time.Minute}
			vcReq := &vcv1alpha1.VerifiableCredentialRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      vcReqName,
					Namespace: vcReqNs,
				},
				Spec: vcv1alpha1.VerifiableCredentialRequestSpec{
					IssuerRef:      vcv1alpha1.LocalObjectReference{Name: issuerName},
					CredentialType: credType,
					Format:         "jwt_vc_json",
					TargetSecretRef: vcv1alpha1.TargetSecretReference{
						Name: targetSecret,
						Key:  "credential",
					},
					RenewBefore: &renewBefore,
				},
			}
			Expect(k8sClient.Create(ctx, vcReq)).To(Succeed())

			setupHappyPath()
		})

		AfterEach(func() {
			deleteResource(ctx, &vcv1alpha1.VerifiableCredentialRequest{}, vcReqName)
			deleteResource(ctx, &vcv1alpha1.CredentialIssuer{}, issuerName)
			deleteResource(ctx, &corev1.Secret{}, authSecretName)
		})

		It("should requeue earlier based on custom renewBefore", func() {
			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			// Expiry in 1 hour, renewBefore 30 minutes → requeue in ~30 minutes.
			Expect(result.RequeueAfter).To(BeNumerically(">", 25*time.Minute))
			Expect(result.RequeueAfter).To(BeNumerically("<", 35*time.Minute))
		})
	})

	Context("injectable clock: deterministic renewal scheduling", func() {
		var fakeClock *FakeClock

		BeforeEach(func() {
			createReadyIssuer(ctx)
			createAuthSecret(ctx)
			createVCRequest(ctx)

			fakeClock = &FakeClock{
				CurrentTime: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC),
			}
			reconciler.Clock = fakeClock

			// Credential valid for 1 hour from fake clock time.
			setupHappyPathWithClock(fakeClock.CurrentTime, 1*time.Hour)
		})

		AfterEach(func() {
			deleteResource(ctx, &vcv1alpha1.VerifiableCredentialRequest{}, vcReqName)
			deleteResource(ctx, &vcv1alpha1.CredentialIssuer{}, issuerName)
			deleteResource(ctx, &corev1.Secret{}, authSecretName)
		})

		It("should use the injected clock for renewal computation", func() {
			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			// Expiry at 13:00 UTC, renewBefore default 5m, so renewal at 12:55 UTC.
			// Requeue = 12:55 - 12:00 = 55 minutes.
			Expect(result.RequeueAfter).To(Equal(55 * time.Minute))
		})

		It("should compute correct requeue after time advancement", func() {
			// First reconciliation at 12:00 UTC.
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			// Advance clock past renewal time (12:55) to trigger re-issuance.
			fakeClock.Advance(56 * time.Minute)
			// Set up new credential for second reconciliation.
			setupHappyPathWithClock(fakeClock.CurrentTime, 1*time.Hour)

			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			// New credential expires at 13:56, renewBefore 5m, renewal at 13:51.
			// Requeue = 13:51 - 12:56 = 55 minutes.
			Expect(result.RequeueAfter).To(Equal(55 * time.Minute))
		})

		It("should set correct NextRenewalTime and CredentialExpiryTime", func() {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			status := getVCRequestStatus(ctx)
			// Credential expires at 13:00 UTC.
			expectedExpiry := time.Date(2026, 6, 1, 13, 0, 0, 0, time.UTC)
			Expect(status.CredentialExpiryTime).NotTo(BeNil())
			Expect(status.CredentialExpiryTime.UTC()).To(BeTemporally("~", expectedExpiry, 2*time.Second))

			// NextRenewalTime = expiry - 5m = 12:55 UTC.
			expectedRenewal := time.Date(2026, 6, 1, 12, 55, 0, 0, time.UTC)
			Expect(status.NextRenewalTime).NotTo(BeNil())
			Expect(status.NextRenewalTime.UTC()).To(BeTemporally("~", expectedRenewal, 2*time.Second))
		})

		It("should trigger immediate renewal for expired credential", func() {
			// Advance clock past expiry.
			fakeClock.SetTime(time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC))

			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			// Renewal is overdue — requeue at MinRenewalInterval.
			Expect(result.RequeueAfter).To(Equal(credential.MinRenewalInterval))
		})
	})

	Context("Prometheus metrics: initial issuance", func() {
		var testMetrics *VCRequestMetrics

		BeforeEach(func() {
			createReadyIssuer(ctx)
			createAuthSecret(ctx)
			createVCRequest(ctx)
			setupHappyPath()

			// Create fresh metrics (not registered — we just test the counters directly).
			testMetrics = NewVCRequestMetrics()
			reconciler.Metrics = testMetrics
		})

		AfterEach(func() {
			deleteResource(ctx, &vcv1alpha1.VerifiableCredentialRequest{}, vcReqName)
			deleteResource(ctx, &vcv1alpha1.CredentialIssuer{}, issuerName)
			deleteResource(ctx, &corev1.Secret{}, authSecretName)
		})

		It("should increment credentials_issued_total on initial issuance", func() {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			issued := getCounterValue(testMetrics.CredentialsIssuedTotal, vcReqNs, vcReqName, credType)
			Expect(issued).To(Equal(float64(1)))

			renewed := getCounterValue(testMetrics.CredentialsRenewedTotal, vcReqNs, vcReqName, credType)
			Expect(renewed).To(Equal(float64(0)))
		})

		It("should set credential_expiry_seconds gauge", func() {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			expiry := getGaugeValue(testMetrics.CredentialExpirySeconds, vcReqNs, vcReqName, credType)
			// Expiry should be a future Unix timestamp (within 2 hours from now).
			Expect(expiry).To(BeNumerically(">", float64(time.Now().Unix())))
			Expect(expiry).To(BeNumerically("<", float64(time.Now().Add(2*time.Hour).Unix())))
		})
	})

	Context("Prometheus metrics: renewal", func() {
		var testMetrics *VCRequestMetrics
		var fakeClock *FakeClock

		BeforeEach(func() {
			createReadyIssuer(ctx)
			createAuthSecret(ctx)
			createVCRequest(ctx)

			fakeClock = &FakeClock{
				CurrentTime: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC),
			}
			reconciler.Clock = fakeClock
			setupHappyPathWithClock(fakeClock.CurrentTime, 1*time.Hour)

			testMetrics = NewVCRequestMetrics()
			reconciler.Metrics = testMetrics
		})

		AfterEach(func() {
			deleteResource(ctx, &vcv1alpha1.VerifiableCredentialRequest{}, vcReqName)
			deleteResource(ctx, &vcv1alpha1.CredentialIssuer{}, issuerName)
			deleteResource(ctx, &corev1.Secret{}, authSecretName)
		})

		It("should increment credentials_renewed_total on renewal", func() {
			// First reconciliation — initial issuance.
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			// Advance clock past renewal time to trigger re-issuance.
			fakeClock.SetTime(time.Date(2026, 6, 1, 12, 56, 0, 0, time.UTC))
			setupHappyPathWithClock(fakeClock.CurrentTime, 1*time.Hour)

			// Second reconciliation — renewal.
			_, err = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			issued := getCounterValue(testMetrics.CredentialsIssuedTotal, vcReqNs, vcReqName, credType)
			Expect(issued).To(Equal(float64(1)))

			renewed := getCounterValue(testMetrics.CredentialsRenewedTotal, vcReqNs, vcReqName, credType)
			Expect(renewed).To(Equal(float64(1)))
		})

		It("should accumulate renewal count over multiple renewals", func() {
			// Initial issuance + 3 renewals, advancing clock each time.
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			for i := range 3 {
				fakeClock.Advance(56 * time.Minute)
				setupHappyPathWithClock(fakeClock.CurrentTime, 1*time.Hour)

				_, err := reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: typeNamespacedName,
				})
				Expect(err).NotTo(HaveOccurred())
				_ = i
			}

			issued := getCounterValue(testMetrics.CredentialsIssuedTotal, vcReqNs, vcReqName, credType)
			Expect(issued).To(Equal(float64(1)))

			renewed := getCounterValue(testMetrics.CredentialsRenewedTotal, vcReqNs, vcReqName, credType)
			Expect(renewed).To(Equal(float64(3)))
		})
	})

	Context("Prometheus metrics: errors", func() {
		var testMetrics *VCRequestMetrics

		BeforeEach(func() {
			createVCRequest(ctx)

			testMetrics = NewVCRequestMetrics()
			reconciler.Metrics = testMetrics
		})

		AfterEach(func() {
			deleteResource(ctx, &vcv1alpha1.VerifiableCredentialRequest{}, vcReqName)
			deleteResource(ctx, &vcv1alpha1.CredentialIssuer{}, issuerName)
			deleteResource(ctx, &corev1.Secret{}, authSecretName)
		})

		It("should increment credentials_errors_total on issuer not found", func() {
			_, _ = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})

			errors := getCounterValue(testMetrics.CredentialsErrorsTotal, vcReqNs, vcReqName, vcv1alpha1.ReasonIssuerNotFound)
			Expect(errors).To(Equal(float64(1)))
		})

		It("should increment credentials_errors_total on auth secret missing", func() {
			createReadyIssuer(ctx)
			// No auth secret created.

			_, _ = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})

			errors := getCounterValue(testMetrics.CredentialsErrorsTotal, vcReqNs, vcReqName, vcv1alpha1.ReasonAuthSecretNotFound)
			Expect(errors).To(Equal(float64(1)))
		})

		It("should increment credentials_errors_total on token request failure", func() {
			createReadyIssuer(ctx)
			createAuthSecret(ctx)
			mockOID4VCI.obtainAccessTokenFunc = func(_ context.Context, _ string, _ oid4vci.TokenAuth) (*oid4vci.TokenResponse, error) {
				return nil, fmt.Errorf("token error")
			}

			_, _ = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})

			errors := getCounterValue(testMetrics.CredentialsErrorsTotal, vcReqNs, vcReqName, vcv1alpha1.ReasonCredentialRequestFailed)
			Expect(errors).To(Equal(float64(1)))
		})

		It("should increment credentials_errors_total on storage failure", func() {
			createReadyIssuer(ctx)
			createAuthSecret(ctx)
			setupHappyPath()
			mockStore.storeFunc = func(_ context.Context, _ credentialstore.TargetRef, _ *credentialstore.CredentialData) error {
				return fmt.Errorf("storage error")
			}

			_, _ = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})

			errors := getCounterValue(testMetrics.CredentialsErrorsTotal, vcReqNs, vcReqName, vcv1alpha1.ReasonStorageFailed)
			Expect(errors).To(Equal(float64(1)))
		})
	})

	Context("nil metrics: no panic when metrics not configured", func() {
		BeforeEach(func() {
			createReadyIssuer(ctx)
			createAuthSecret(ctx)
			createVCRequest(ctx)
			setupHappyPath()

			// Ensure Metrics is nil (default from BeforeEach).
			reconciler.Metrics = nil
		})

		AfterEach(func() {
			deleteResource(ctx, &vcv1alpha1.VerifiableCredentialRequest{}, vcReqName)
			deleteResource(ctx, &vcv1alpha1.CredentialIssuer{}, issuerName)
			deleteResource(ctx, &corev1.Secret{}, authSecretName)
		})

		It("should succeed without panicking when metrics are nil", func() {
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("startup reconciliation: imminent expiry", func() {
		var fakeClock *FakeClock

		BeforeEach(func() {
			createReadyIssuer(ctx)
			createAuthSecret(ctx)
			createVCRequest(ctx)

			// Set up clock at credential creation time.
			fakeClock = &FakeClock{
				CurrentTime: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC),
			}
			reconciler.Clock = fakeClock

			// Credential valid for only 10 minutes from the fake clock time.
			setupHappyPathWithClock(fakeClock.CurrentTime, 10*time.Minute)
		})

		AfterEach(func() {
			deleteResource(ctx, &vcv1alpha1.VerifiableCredentialRequest{}, vcReqName)
			deleteResource(ctx, &vcv1alpha1.CredentialIssuer{}, issuerName)
			deleteResource(ctx, &corev1.Secret{}, authSecretName)
		})

		It("should schedule renewal soon for short-lived credentials", func() {
			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			// Credential expires at 12:10, renewBefore=5m → renewal at 12:05.
			// Requeue = 12:05 - 12:00 = 5 minutes.
			Expect(result.RequeueAfter).To(Equal(5 * time.Minute))
		})

		It("should trigger immediate renewal if renewal window has passed", func() {
			// Advance clock to 12:06 — past the 12:05 renewal time.
			fakeClock.Advance(6 * time.Minute)

			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			// Renewal time already passed, use MinRenewalInterval.
			Expect(result.RequeueAfter).To(Equal(credential.MinRenewalInterval))
		})
	})

	Context("holder key binding: JWK binding via holderKeyRef", func() {
		const holderKeySecretName = "test-holder-key"

		// generateHolderKeyPEM creates an ECDSA P-256 key pair and returns the
		// PEM-encoded private key and the private key itself for assertion.
		generateHolderKeyPEM := func() []byte {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			Expect(err).NotTo(HaveOccurred())

			derBytes, err := x509.MarshalECPrivateKey(key)
			Expect(err).NotTo(HaveOccurred())

			pemBytes := pem.EncodeToMemory(&pem.Block{
				Type:  "EC PRIVATE KEY",
				Bytes: derBytes,
			})
			return pemBytes
		}

		BeforeEach(func() {
			createReadyIssuer(ctx)
			createAuthSecret(ctx)
			setupHappyPath()
		})

		AfterEach(func() {
			deleteResource(ctx, &vcv1alpha1.VerifiableCredentialRequest{}, vcReqName)
			deleteResource(ctx, &vcv1alpha1.CredentialIssuer{}, issuerName)
			deleteResource(ctx, &corev1.Secret{}, authSecretName)
			deleteResource(ctx, &corev1.Secret{}, holderKeySecretName)
		})

		It("should include proof-of-possession JWT signed by holder key", func() {
			pemData := generateHolderKeyPEM()

			holderSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      holderKeySecretName,
					Namespace: vcReqNs,
				},
				Data: map[string][]byte{
					HolderKeySecretKeyPEM: pemData,
				},
			}
			Expect(k8sClient.Create(ctx, holderSecret)).To(Succeed())

			vcReq := &vcv1alpha1.VerifiableCredentialRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      vcReqName,
					Namespace: vcReqNs,
				},
				Spec: vcv1alpha1.VerifiableCredentialRequestSpec{
					IssuerRef:      vcv1alpha1.LocalObjectReference{Name: issuerName},
					CredentialType: credType,
					Format:         "jwt_vc_json",
					TargetSecretRef: vcv1alpha1.TargetSecretReference{
						Name: targetSecret,
						Key:  "credential",
					},
					HolderKeyRef: &vcv1alpha1.SecretReference{Name: holderKeySecretName},
				},
			}
			Expect(k8sClient.Create(ctx, vcReq)).To(Succeed())

			var capturedReq oid4vci.CredentialRequest
			mockOID4VCI.requestCredentialFunc = func(_ context.Context, _ string, _ string, req oid4vci.CredentialRequest) (*oid4vci.CredentialResponse, error) {
				capturedReq = req
				now := time.Now()
				expiry := now.Add(1 * time.Hour)
				return &oid4vci.CredentialResponse{
					Credential: buildTestJWTWithExpiry(now, expiry),
					Format:     "jwt_vc_json",
				}, nil
			}

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(capturedReq.Proof).NotTo(BeNil())
			Expect(capturedReq.Proof.ProofType).To(Equal(oid4vci.ProofTypeJWT))
			Expect(capturedReq.Proof.JWT).NotTo(BeEmpty())

			// Verify the proof JWT can be parsed and is signed by the holder key.
			claims, verifyErr := oid4vci.VerifyProofJWT(capturedReq.Proof.JWT)
			Expect(verifyErr).NotTo(HaveOccurred())
			Expect(claims).NotTo(BeNil())
		})

		It("should use proofs (plural) format for keycloak issuer type", func() {
			// Delete the generic issuer created by BeforeEach and create a keycloak one.
			deleteResource(ctx, &vcv1alpha1.CredentialIssuer{}, issuerName)
			keycloakIssuer := &vcv1alpha1.CredentialIssuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      issuerName,
					Namespace: vcReqNs,
				},
				Spec: vcv1alpha1.CredentialIssuerSpec{
					IssuerURL:     "https://issuer.example.com",
					IssuerType:    "keycloak",
					AuthSecretRef: vcv1alpha1.SecretReference{Name: authSecretName},
				},
			}
			Expect(k8sClient.Create(ctx, keycloakIssuer)).To(Succeed())
			Eventually(func() error {
				var fetched vcv1alpha1.CredentialIssuer
				if err := k8sClient.Get(ctx, types.NamespacedName{Name: issuerName, Namespace: vcReqNs}, &fetched); err != nil {
					return err
				}
				fetched.Status.CredentialEndpoint = "https://issuer.example.com/credentials"
				fetched.Status.TokenEndpoint = "https://issuer.example.com/token"
				fetched.Status.IssuerIdentifier = "https://issuer.example.com"
				fetched.Status.SupportedCredentialTypes = []string{"VerifiableCredential"}
				meta.SetStatusCondition(&fetched.Status.Conditions, metav1.Condition{
					Type:               vcv1alpha1.ConditionTypeReady,
					Status:             metav1.ConditionTrue,
					Reason:             vcv1alpha1.ReasonMetadataDiscovered,
					Message:            "Issuer is ready",
					ObservedGeneration: fetched.Generation,
				})
				return k8sClient.Status().Update(ctx, &fetched)
			}).Should(Succeed())

			pemData := generateHolderKeyPEM()
			holderSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      holderKeySecretName,
					Namespace: vcReqNs,
				},
				Data: map[string][]byte{
					HolderKeySecretKeyPEM: pemData,
				},
			}
			Expect(k8sClient.Create(ctx, holderSecret)).To(Succeed())

			vcReq := &vcv1alpha1.VerifiableCredentialRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      vcReqName,
					Namespace: vcReqNs,
				},
				Spec: vcv1alpha1.VerifiableCredentialRequestSpec{
					IssuerRef:      vcv1alpha1.LocalObjectReference{Name: issuerName},
					CredentialType: credType,
					Format:         "jwt_vc_json",
					TargetSecretRef: vcv1alpha1.TargetSecretReference{
						Name: targetSecret,
						Key:  "credential",
					},
					HolderKeyRef: &vcv1alpha1.SecretReference{Name: holderKeySecretName},
				},
			}
			Expect(k8sClient.Create(ctx, vcReq)).To(Succeed())

			var capturedReq oid4vci.CredentialRequest
			mockOID4VCI.requestCredentialFunc = func(_ context.Context, _ string, _ string, req oid4vci.CredentialRequest) (*oid4vci.CredentialResponse, error) {
				capturedReq = req
				now := time.Now()
				expiry := now.Add(1 * time.Hour)
				return &oid4vci.CredentialResponse{
					Credential: buildTestJWTWithExpiry(now, expiry),
					Format:     "jwt_vc_json",
				}, nil
			}

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(capturedReq.Proof).To(BeNil(), "proof (singular) should not be set for keycloak issuers")
			Expect(capturedReq.Proofs).NotTo(BeNil(), "proofs (plural) must be set for keycloak issuers")
			Expect(capturedReq.Proofs[oid4vci.ProofTypeJWT]).To(HaveLen(1))
			Expect(capturedReq.Proofs[oid4vci.ProofTypeJWT][0]).NotTo(BeEmpty())

			// Verify the proof JWT can be parsed.
			proofJWT := capturedReq.Proofs[oid4vci.ProofTypeJWT][0]
			claims, verifyErr := oid4vci.VerifyProofJWT(proofJWT)
			Expect(verifyErr).NotTo(HaveOccurred())
			Expect(claims).NotTo(BeNil())
		})

		It("should use tls.key as fallback key name", func() {
			pemData := generateHolderKeyPEM()

			holderSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      holderKeySecretName,
					Namespace: vcReqNs,
				},
				Data: map[string][]byte{
					HolderKeySecretKeyTLS: pemData,
				},
			}
			Expect(k8sClient.Create(ctx, holderSecret)).To(Succeed())

			vcReq := &vcv1alpha1.VerifiableCredentialRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      vcReqName,
					Namespace: vcReqNs,
				},
				Spec: vcv1alpha1.VerifiableCredentialRequestSpec{
					IssuerRef:      vcv1alpha1.LocalObjectReference{Name: issuerName},
					CredentialType: credType,
					Format:         "jwt_vc_json",
					TargetSecretRef: vcv1alpha1.TargetSecretReference{
						Name: targetSecret,
						Key:  "credential",
					},
					HolderKeyRef: &vcv1alpha1.SecretReference{Name: holderKeySecretName},
				},
			}
			Expect(k8sClient.Create(ctx, vcReq)).To(Succeed())

			var capturedReq oid4vci.CredentialRequest
			mockOID4VCI.requestCredentialFunc = func(_ context.Context, _ string, _ string, req oid4vci.CredentialRequest) (*oid4vci.CredentialResponse, error) {
				capturedReq = req
				now := time.Now()
				expiry := now.Add(1 * time.Hour)
				return &oid4vci.CredentialResponse{
					Credential: buildTestJWTWithExpiry(now, expiry),
					Format:     "jwt_vc_json",
				}, nil
			}

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(capturedReq.Proof).NotTo(BeNil())
			Expect(capturedReq.Proof.JWT).NotTo(BeEmpty())
		})

		It("should not include proof when holderKeyRef is not set", func() {
			createVCRequest(ctx)

			var capturedReq oid4vci.CredentialRequest
			mockOID4VCI.requestCredentialFunc = func(_ context.Context, _ string, _ string, req oid4vci.CredentialRequest) (*oid4vci.CredentialResponse, error) {
				capturedReq = req
				now := time.Now()
				expiry := now.Add(1 * time.Hour)
				return &oid4vci.CredentialResponse{
					Credential: buildTestJWTWithExpiry(now, expiry),
					Format:     "jwt_vc_json",
				}, nil
			}

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(capturedReq.Proof).To(BeNil())
		})
	})

	Context("holder key binding: DID binding via holderDID", func() {
		const holderKeySecretName = "test-holder-key-did"

		BeforeEach(func() {
			createReadyIssuer(ctx)
			createAuthSecret(ctx)
			setupHappyPath()
		})

		AfterEach(func() {
			deleteResource(ctx, &vcv1alpha1.VerifiableCredentialRequest{}, vcReqName)
			deleteResource(ctx, &vcv1alpha1.CredentialIssuer{}, issuerName)
			deleteResource(ctx, &corev1.Secret{}, authSecretName)
			deleteResource(ctx, &corev1.Secret{}, holderKeySecretName)
		})

		It("should include proof JWT when holderKeyRef and holderDID are both set", func() {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			Expect(err).NotTo(HaveOccurred())
			derBytes, err := x509.MarshalECPrivateKey(key)
			Expect(err).NotTo(HaveOccurred())
			pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: derBytes})

			holderSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      holderKeySecretName,
					Namespace: vcReqNs,
				},
				Data: map[string][]byte{
					HolderKeySecretKeyPEM: pemBytes,
				},
			}
			Expect(k8sClient.Create(ctx, holderSecret)).To(Succeed())

			testDID := "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169"
			vcReq := &vcv1alpha1.VerifiableCredentialRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      vcReqName,
					Namespace: vcReqNs,
				},
				Spec: vcv1alpha1.VerifiableCredentialRequestSpec{
					IssuerRef:      vcv1alpha1.LocalObjectReference{Name: issuerName},
					CredentialType: credType,
					Format:         "jwt_vc_json",
					TargetSecretRef: vcv1alpha1.TargetSecretReference{
						Name: targetSecret,
						Key:  "credential",
					},
					HolderKeyRef: &vcv1alpha1.SecretReference{Name: holderKeySecretName},
					HolderDID:    testDID,
				},
			}
			Expect(k8sClient.Create(ctx, vcReq)).To(Succeed())

			var capturedReq oid4vci.CredentialRequest
			mockOID4VCI.requestCredentialFunc = func(_ context.Context, _ string, _ string, req oid4vci.CredentialRequest) (*oid4vci.CredentialResponse, error) {
				capturedReq = req
				now := time.Now()
				expiry := now.Add(1 * time.Hour)
				return &oid4vci.CredentialResponse{
					Credential: buildTestJWTWithExpiry(now, expiry),
					Format:     "jwt_vc_json",
				}, nil
			}

			_, err = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(capturedReq.Proof).NotTo(BeNil())
			Expect(capturedReq.Proof.ProofType).To(Equal(oid4vci.ProofTypeJWT))
			Expect(capturedReq.Proof.JWT).NotTo(BeEmpty())
		})
	})

	Context("holder key binding: error cases", func() {
		const holderKeySecretName = "test-holder-key-err"

		BeforeEach(func() {
			createReadyIssuer(ctx)
			createAuthSecret(ctx)
			setupHappyPath()
		})

		AfterEach(func() {
			deleteResource(ctx, &vcv1alpha1.VerifiableCredentialRequest{}, vcReqName)
			deleteResource(ctx, &vcv1alpha1.CredentialIssuer{}, issuerName)
			deleteResource(ctx, &corev1.Secret{}, authSecretName)
			deleteResource(ctx, &corev1.Secret{}, holderKeySecretName)
		})

		It("should set HolderKeyInvalid error when holderDID is set without holderKeyRef", func() {
			vcReq := &vcv1alpha1.VerifiableCredentialRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      vcReqName,
					Namespace: vcReqNs,
				},
				Spec: vcv1alpha1.VerifiableCredentialRequestSpec{
					IssuerRef:      vcv1alpha1.LocalObjectReference{Name: issuerName},
					CredentialType: credType,
					Format:         "jwt_vc_json",
					TargetSecretRef: vcv1alpha1.TargetSecretReference{
						Name: targetSecret,
						Key:  "credential",
					},
					HolderDID: "did:key:z6MkhaXgoo#key-1",
				},
			}
			Expect(k8sClient.Create(ctx, vcReq)).To(Succeed())

			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(DefaultConfigErrorRequeueInterval))

			status := getVCRequestStatus(ctx)
			errorCondition := meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeError)
			Expect(errorCondition).NotTo(BeNil())
			Expect(errorCondition.Status).To(Equal(metav1.ConditionTrue))
			Expect(errorCondition.Reason).To(Equal(vcv1alpha1.ReasonHolderKeyInvalid))
		})

		It("should set HolderKeyInvalid error when holder key Secret is not found", func() {
			vcReq := &vcv1alpha1.VerifiableCredentialRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      vcReqName,
					Namespace: vcReqNs,
				},
				Spec: vcv1alpha1.VerifiableCredentialRequestSpec{
					IssuerRef:      vcv1alpha1.LocalObjectReference{Name: issuerName},
					CredentialType: credType,
					Format:         "jwt_vc_json",
					TargetSecretRef: vcv1alpha1.TargetSecretReference{
						Name: targetSecret,
						Key:  "credential",
					},
					HolderKeyRef: &vcv1alpha1.SecretReference{Name: "nonexistent-secret"},
				},
			}
			Expect(k8sClient.Create(ctx, vcReq)).To(Succeed())

			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(DefaultConfigErrorRequeueInterval))

			status := getVCRequestStatus(ctx)
			errorCondition := meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeError)
			Expect(errorCondition).NotTo(BeNil())
			Expect(errorCondition.Reason).To(Equal(vcv1alpha1.ReasonHolderKeyInvalid))
		})

		It("should set HolderKeyInvalid error when Secret is missing key data", func() {
			holderSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      holderKeySecretName,
					Namespace: vcReqNs,
				},
				Data: map[string][]byte{
					"wrong-key": []byte("some-data"),
				},
			}
			Expect(k8sClient.Create(ctx, holderSecret)).To(Succeed())

			vcReq := &vcv1alpha1.VerifiableCredentialRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      vcReqName,
					Namespace: vcReqNs,
				},
				Spec: vcv1alpha1.VerifiableCredentialRequestSpec{
					IssuerRef:      vcv1alpha1.LocalObjectReference{Name: issuerName},
					CredentialType: credType,
					Format:         "jwt_vc_json",
					TargetSecretRef: vcv1alpha1.TargetSecretReference{
						Name: targetSecret,
						Key:  "credential",
					},
					HolderKeyRef: &vcv1alpha1.SecretReference{Name: holderKeySecretName},
				},
			}
			Expect(k8sClient.Create(ctx, vcReq)).To(Succeed())

			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(DefaultConfigErrorRequeueInterval))

			status := getVCRequestStatus(ctx)
			errorCondition := meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeError)
			Expect(errorCondition).NotTo(BeNil())
			Expect(errorCondition.Reason).To(Equal(vcv1alpha1.ReasonHolderKeyInvalid))
			Expect(errorCondition.Message).To(ContainSubstring("missing required key"))
		})

		It("should set HolderKeyInvalid error when Secret contains invalid PEM data", func() {
			holderSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      holderKeySecretName,
					Namespace: vcReqNs,
				},
				Data: map[string][]byte{
					HolderKeySecretKeyPEM: []byte("not-valid-pem-data"),
				},
			}
			Expect(k8sClient.Create(ctx, holderSecret)).To(Succeed())

			vcReq := &vcv1alpha1.VerifiableCredentialRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      vcReqName,
					Namespace: vcReqNs,
				},
				Spec: vcv1alpha1.VerifiableCredentialRequestSpec{
					IssuerRef:      vcv1alpha1.LocalObjectReference{Name: issuerName},
					CredentialType: credType,
					Format:         "jwt_vc_json",
					TargetSecretRef: vcv1alpha1.TargetSecretReference{
						Name: targetSecret,
						Key:  "credential",
					},
					HolderKeyRef: &vcv1alpha1.SecretReference{Name: holderKeySecretName},
				},
			}
			Expect(k8sClient.Create(ctx, vcReq)).To(Succeed())

			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(DefaultConfigErrorRequeueInterval))

			status := getVCRequestStatus(ctx)
			errorCondition := meta.FindStatusCondition(status.Conditions, vcv1alpha1.ConditionTypeError)
			Expect(errorCondition).NotTo(BeNil())
			Expect(errorCondition.Reason).To(Equal(vcv1alpha1.ReasonHolderKeyInvalid))
			Expect(errorCondition.Message).To(ContainSubstring("invalid key data"))
		})

		It("should record a warning event for holder key errors", func() {
			vcReq := &vcv1alpha1.VerifiableCredentialRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name:      vcReqName,
					Namespace: vcReqNs,
				},
				Spec: vcv1alpha1.VerifiableCredentialRequestSpec{
					IssuerRef:      vcv1alpha1.LocalObjectReference{Name: issuerName},
					CredentialType: credType,
					Format:         "jwt_vc_json",
					TargetSecretRef: vcv1alpha1.TargetSecretReference{
						Name: targetSecret,
						Key:  "credential",
					},
					HolderDID: "did:key:z6MkhaXgoo#key-1",
				},
			}
			Expect(k8sClient.Create(ctx, vcReq)).To(Succeed())

			_, _ = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})

			var event string
			Expect(eventRecorder.Events).Should(Receive(&event))
			Expect(event).To(ContainSubstring(vcv1alpha1.ReasonHolderKeyInvalid))
		})
	})
})

var _ = Describe("resolveFormat", func() {
	var reconciler *VerifiableCredentialRequestReconciler

	BeforeEach(func() {
		reconciler = &VerifiableCredentialRequestReconciler{}
	})

	It("should return the spec format when specified", func() {
		Expect(reconciler.resolveFormat("ldp_vc")).To(Equal("ldp_vc"))
	})

	It("should return the default format when empty", func() {
		Expect(reconciler.resolveFormat("")).To(Equal(vcv1alpha1.DefaultCredentialFormat))
	})
})

var _ = Describe("resolveRenewBefore", func() {
	var reconciler *VerifiableCredentialRequestReconciler

	BeforeEach(func() {
		reconciler = &VerifiableCredentialRequestReconciler{}
	})

	It("should return the spec duration when specified", func() {
		d := metav1.Duration{Duration: 10 * time.Minute}
		Expect(reconciler.resolveRenewBefore(&d)).To(Equal(10 * time.Minute))
	})

	It("should return the default when nil", func() {
		Expect(reconciler.resolveRenewBefore(nil)).To(Equal(credential.DefaultRenewBeforeDuration))
	})
})

var _ = Describe("Clock implementations", func() {
	Context("RealClock", func() {
		It("should return a time close to now", func() {
			clock := RealClock{}
			before := time.Now()
			result := clock.Now()
			after := time.Now()

			Expect(result).To(BeTemporally(">=", before))
			Expect(result).To(BeTemporally("<=", after))
		})
	})

	Context("FakeClock", func() {
		It("should return the set time", func() {
			t := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			clock := &FakeClock{CurrentTime: t}
			Expect(clock.Now()).To(Equal(t))
		})

		It("should advance time by the given duration", func() {
			t := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			clock := &FakeClock{CurrentTime: t}
			clock.Advance(1 * time.Hour)
			Expect(clock.Now()).To(Equal(t.Add(1 * time.Hour)))
		})

		It("should set time to a specific point", func() {
			clock := &FakeClock{CurrentTime: time.Now()}
			newTime := time.Date(2030, 12, 31, 23, 59, 59, 0, time.UTC)
			clock.SetTime(newTime)
			Expect(clock.Now()).To(Equal(newTime))
		})
	})
})

var _ = Describe("VCRequestMetrics", func() {
	It("should create metrics with correct names", func() {
		m := NewVCRequestMetrics()
		Expect(m.CredentialsIssuedTotal).NotTo(BeNil())
		Expect(m.CredentialsRenewedTotal).NotTo(BeNil())
		Expect(m.CredentialsErrorsTotal).NotTo(BeNil())
		Expect(m.CredentialExpirySeconds).NotTo(BeNil())

		// Verify we can create metric instances with expected labels.
		counter, err := m.CredentialsIssuedTotal.GetMetricWithLabelValues("ns", "name", "type")
		Expect(err).NotTo(HaveOccurred())
		Expect(counter).NotTo(BeNil())

		errCounter, err := m.CredentialsErrorsTotal.GetMetricWithLabelValues("ns", "name", "reason")
		Expect(err).NotTo(HaveOccurred())
		Expect(errCounter).NotTo(BeNil())

		gauge, err := m.CredentialExpirySeconds.GetMetricWithLabelValues("ns", "name", "type")
		Expect(err).NotTo(HaveOccurred())
		Expect(gauge).NotTo(BeNil())
	})
})
