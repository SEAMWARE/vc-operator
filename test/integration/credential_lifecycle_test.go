//go:build integration

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

package integration

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"

	vcv1alpha1 "github.com/SEAMWARE/vc-operator/api/v1alpha1"
)

// Resource name constants used across test scenarios.
const (
	// issuerName is the default name for test CredentialIssuer resources.
	issuerName = "test-issuer"

	// authSecretName is the default name for test authentication Secrets.
	authSecretName = "test-auth-secret"

	// vcrName is the default name for test VerifiableCredentialRequest resources.
	vcrName = "test-vcr"

	// targetSecretName is the default name for the credential target Secret.
	targetSecretName = "test-credential-secret"

	// credentialKey is the data key used for credential storage in Secrets.
	credentialKey = "credential"

	// jwtSegmentCount is the expected number of segments in a compact JWT.
	jwtSegmentCount = 3
)

var _ = Describe("Credential Lifecycle", func() {
	var ns string

	BeforeEach(func() {
		ns = fmt.Sprintf("test-%s", generateRandomSuffix())
		createNamespace(ctx, k8sClient, ns)
		// Ensure the mock issuer is in a clean state for each test.
		mockIssuer.SetFailToken(false)
		mockIssuer.SetFailCredential(false)
		mockIssuer.SetCredentialExpiry(defaultCredentialExpiry)
		mockIssuer.ResetIssueCount()
	})

	AfterEach(func() {
		deleteNamespace(ctx, k8sClient, ns)
	})

	// ---------------------------------------------------------------
	// Happy Path: Full credential lifecycle
	// ---------------------------------------------------------------
	Context("Happy path", func() {
		It("should obtain a credential and store it in the target Secret", func() {
			By("creating the auth Secret with valid client credentials")
			createAuthSecret(ctx, k8sClient, ns, authSecretName,
				defaultValidClientID, defaultValidClientSecret)

			By("creating a CredentialIssuer pointing to the mock Keycloak issuer")
			createCredentialIssuer(ctx, k8sClient, ns, issuerName,
				mockIssuer.URL(), authSecretName)

			By("waiting for the CredentialIssuer to become Ready")
			waitForIssuerReady(ctx, k8sClient, ns, issuerName)

			By("verifying the CredentialIssuer status has discovered metadata")
			issuer := getCredentialIssuer(ctx, k8sClient, ns, issuerName)
			Expect(issuer.Status.CredentialEndpoint).To(ContainSubstring("/credential"))
			Expect(issuer.Status.TokenEndpoint).To(ContainSubstring("/token"))
			Expect(issuer.Status.SupportedCredentialTypes).To(ContainElement(defaultCredentialType))
			Expect(issuer.Status.LastMetadataFetchTime).NotTo(BeNil())

			By("creating a VerifiableCredentialRequest")
			createVCRequest(ctx, k8sClient, ns, vcrName,
				issuerName, defaultCredentialType, targetSecretName)

			By("waiting for the VerifiableCredentialRequest to become Ready")
			waitForVCRequestReady(ctx, k8sClient, ns, vcrName)

			By("verifying the target Secret contains the credential")
			secret := assertSecretHasCredential(ctx, k8sClient, ns, targetSecretName, credentialKey)

			By("verifying the credential is a valid JWT")
			credData := string(secret.Data[credentialKey])
			segments := strings.Split(credData, ".")
			Expect(segments).To(HaveLen(jwtSegmentCount), "JWT should have 3 dot-separated segments")

			By("verifying the Secret has expiry and issuedAt timestamps")
			Expect(secret.Data).To(HaveKey("expiryTimestamp"))
			Expect(secret.Data).To(HaveKey("issuedAtTimestamp"))

			By("verifying the VCR status has correct fields")
			vcr := getVCRequest(ctx, k8sClient, ns, vcrName)

			// Conditions.
			readyCond := meta.FindStatusCondition(vcr.Status.Conditions, vcv1alpha1.ConditionTypeReady)
			Expect(readyCond).NotTo(BeNil())
			Expect(readyCond.Status).To(Equal(metav1.ConditionTrue))

			issuedCond := meta.FindStatusCondition(vcr.Status.Conditions, vcv1alpha1.ConditionTypeCredentialIssued)
			Expect(issuedCond).NotTo(BeNil())
			Expect(issuedCond.Status).To(Equal(metav1.ConditionTrue))
			Expect(issuedCond.Reason).To(Equal(vcv1alpha1.ReasonCredentialObtained))

			renewalCond := meta.FindStatusCondition(vcr.Status.Conditions, vcv1alpha1.ConditionTypeRenewalScheduled)
			Expect(renewalCond).NotTo(BeNil())
			Expect(renewalCond.Status).To(Equal(metav1.ConditionTrue))

			// Timestamps.
			Expect(vcr.Status.LastIssuanceTime).NotTo(BeNil())
			Expect(vcr.Status.CredentialExpiryTime).NotTo(BeNil())
			Expect(vcr.Status.NextRenewalTime).NotTo(BeNil())

			// Format.
			Expect(vcr.Status.CredentialFormat).To(Equal(defaultCredentialFormat))

			// The mock issuer should have been called at least once.
			// Note: the controller may re-reconcile on status updates, causing
			// additional issuances beyond the initial one.
			Expect(mockIssuer.IssueCount()).To(BeNumerically(">=", int32(1)),
				"Mock issuer should have been called at least once")

			By("verifying the Secret has an owner reference for garbage collection")
			assertSecretHasOwnerReference(secret, vcr.UID, vcr.Name)
		})
	})

	// ---------------------------------------------------------------
	// Credential Format: jwt_vc_json
	// ---------------------------------------------------------------
	Context("Credential format variants", func() {
		It("should store credentials with jwt_vc_json format metadata", func() {
			By("setting up the full credential pipeline")
			createAuthSecret(ctx, k8sClient, ns, authSecretName,
				defaultValidClientID, defaultValidClientSecret)
			createCredentialIssuer(ctx, k8sClient, ns, issuerName,
				mockIssuer.URL(), authSecretName)
			waitForIssuerReady(ctx, k8sClient, ns, issuerName)
			createVCRequest(ctx, k8sClient, ns, vcrName,
				issuerName, defaultCredentialType, targetSecretName)
			waitForVCRequestReady(ctx, k8sClient, ns, vcrName)

			By("verifying the credential format is correctly stored")
			secret := getSecret(ctx, k8sClient, ns, targetSecretName)
			Expect(string(secret.Data["format"])).To(Equal("jwt_vc_json"))

			By("verifying the VCR status reports the correct format")
			vcr := getVCRequest(ctx, k8sClient, ns, vcrName)
			Expect(vcr.Status.CredentialFormat).To(Equal("jwt_vc_json"))

			By("verifying the JWT payload contains vc claim")
			credJWT := string(secret.Data[credentialKey])
			payload := decodeJWTPayload(credJWT)
			Expect(payload).To(HaveKey("vc"))
			vcClaim, ok := payload["vc"].(map[string]any)
			Expect(ok).To(BeTrue(), "vc claim should be a JSON object")
			Expect(vcClaim).To(HaveKey("type"))
		})
	})

	// ---------------------------------------------------------------
	// Auth Failure: Invalid client credentials
	// ---------------------------------------------------------------
	Context("Authentication failure", func() {
		It("should set Error condition when client credentials are invalid", func() {
			By("creating an auth Secret with WRONG credentials")
			createAuthSecret(ctx, k8sClient, ns, authSecretName,
				"wrong-client-id", "wrong-client-secret")

			By("creating a CredentialIssuer (metadata discovery will succeed)")
			createCredentialIssuer(ctx, k8sClient, ns, issuerName,
				mockIssuer.URL(), authSecretName)
			waitForIssuerReady(ctx, k8sClient, ns, issuerName)

			By("creating a VerifiableCredentialRequest")
			createVCRequest(ctx, k8sClient, ns, vcrName,
				issuerName, defaultCredentialType, targetSecretName)

			By("waiting for the VCR to enter Error state due to token failure")
			waitForVCRequestCondition(ctx, k8sClient, ns, vcrName,
				vcv1alpha1.ConditionTypeError, metav1.ConditionTrue)

			By("verifying Ready is False")
			vcr := getVCRequest(ctx, k8sClient, ns, vcrName)
			readyCond := meta.FindStatusCondition(vcr.Status.Conditions, vcv1alpha1.ConditionTypeReady)
			Expect(readyCond).NotTo(BeNil())
			Expect(readyCond.Status).To(Equal(metav1.ConditionFalse))

			By("verifying the error reason indicates token failure")
			errorCond := meta.FindStatusCondition(vcr.Status.Conditions, vcv1alpha1.ConditionTypeError)
			Expect(errorCond).NotTo(BeNil())
			Expect(errorCond.Reason).To(Equal(vcv1alpha1.ReasonTokenRequestFailed))

			By("verifying no credential was stored")
			// The Error condition with ReasonTokenRequestFailed confirms no token
			// was obtained, so the credential endpoint was never reached. We verify
			// this by checking that the target Secret does not exist.
			Consistently(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Namespace: ns, Name: targetSecretName,
				}, &corev1.Secret{})
			}, consistentlyDuration, pollingInterval).ShouldNot(Succeed(),
				"Target Secret should not be created when auth fails")
		})

		It("should set Error condition when auth Secret is missing", func() {
			By("creating a CredentialIssuer referencing a non-existent Secret")
			issuer := &vcv1alpha1.CredentialIssuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      issuerName,
					Namespace: ns,
				},
				Spec: vcv1alpha1.CredentialIssuerSpec{
					IssuerURL:  mockIssuer.URL(),
					IssuerType: "keycloak",
					AuthSecretRef: vcv1alpha1.SecretReference{
						Name: "nonexistent-secret",
					},
				},
			}
			Expect(k8sClient.Create(ctx, issuer)).To(Succeed())

			By("waiting for the CredentialIssuer to have Error condition")
			waitForIssuerCondition(ctx, k8sClient, ns, issuerName,
				vcv1alpha1.ConditionTypeError, metav1.ConditionTrue)

			By("verifying the issuer is not Ready")
			fetchedIssuer := getCredentialIssuer(ctx, k8sClient, ns, issuerName)
			readyCond := meta.FindStatusCondition(fetchedIssuer.Status.Conditions, vcv1alpha1.ConditionTypeReady)
			Expect(readyCond).NotTo(BeNil())
			Expect(readyCond.Status).To(Equal(metav1.ConditionFalse))
			Expect(readyCond.Reason).To(Equal(vcv1alpha1.ReasonAuthSecretNotFound))
		})
	})

	// ---------------------------------------------------------------
	// Issuer Unavailable: Connection failure
	// ---------------------------------------------------------------
	Context("Issuer unavailable", func() {
		It("should set Error condition when the issuer is unreachable", func() {
			By("creating the auth Secret")
			createAuthSecret(ctx, k8sClient, ns, authSecretName,
				defaultValidClientID, defaultValidClientSecret)

			By("creating a CredentialIssuer pointing to a non-existent URL")
			// Use a localhost port that is not listening to simulate issuer down.
			unreachableURL := "http://127.0.0.1:1"
			createCredentialIssuer(ctx, k8sClient, ns, issuerName,
				unreachableURL, authSecretName)

			By("waiting for the CredentialIssuer to enter Error state")
			waitForIssuerCondition(ctx, k8sClient, ns, issuerName,
				vcv1alpha1.ConditionTypeError, metav1.ConditionTrue)

			By("verifying the error reason indicates metadata fetch failure")
			fetchedIssuer := getCredentialIssuer(ctx, k8sClient, ns, issuerName)
			readyCond := meta.FindStatusCondition(fetchedIssuer.Status.Conditions, vcv1alpha1.ConditionTypeReady)
			Expect(readyCond).NotTo(BeNil())
			Expect(readyCond.Status).To(Equal(metav1.ConditionFalse))
			Expect(readyCond.Reason).To(Equal(vcv1alpha1.ReasonMetadataFetchFailed))
		})

		It("should set IssuerNotReady on VCR when issuer is not Ready", func() {
			By("creating the auth Secret")
			createAuthSecret(ctx, k8sClient, ns, authSecretName,
				defaultValidClientID, defaultValidClientSecret)

			By("creating an unreachable CredentialIssuer")
			unreachableURL := "http://127.0.0.1:1"
			createCredentialIssuer(ctx, k8sClient, ns, issuerName,
				unreachableURL, authSecretName)

			By("waiting for the issuer to have Error condition")
			waitForIssuerCondition(ctx, k8sClient, ns, issuerName,
				vcv1alpha1.ConditionTypeError, metav1.ConditionTrue)

			By("creating a VCR referencing the not-ready issuer")
			createVCRequest(ctx, k8sClient, ns, vcrName,
				issuerName, defaultCredentialType, targetSecretName)

			By("waiting for the VCR to enter Error state due to issuer not ready")
			waitForVCRequestCondition(ctx, k8sClient, ns, vcrName,
				vcv1alpha1.ConditionTypeError, metav1.ConditionTrue)

			By("verifying the error reason is IssuerNotReady")
			vcr := getVCRequest(ctx, k8sClient, ns, vcrName)
			errorCond := meta.FindStatusCondition(vcr.Status.Conditions, vcv1alpha1.ConditionTypeError)
			Expect(errorCond).NotTo(BeNil())
			Expect(errorCond.Reason).To(Equal(vcv1alpha1.ReasonIssuerNotReady))
		})
	})

	// ---------------------------------------------------------------
	// Credential Renewal
	// ---------------------------------------------------------------
	Context("Credential renewal", func() {
		It("should renew the credential on re-reconciliation", func() {
			By("setting up the full credential pipeline")
			createAuthSecret(ctx, k8sClient, ns, authSecretName,
				defaultValidClientID, defaultValidClientSecret)
			createCredentialIssuer(ctx, k8sClient, ns, issuerName,
				mockIssuer.URL(), authSecretName)
			waitForIssuerReady(ctx, k8sClient, ns, issuerName)
			createVCRequest(ctx, k8sClient, ns, vcrName,
				issuerName, defaultCredentialType, targetSecretName)
			waitForVCRequestReady(ctx, k8sClient, ns, vcrName)

			By("verifying initial issuance succeeded")
			Expect(mockIssuer.IssueCount()).To(BeNumerically(">=", int32(1)),
				"Mock issuer should have been called at least once for initial issuance")
			countBeforeTrigger := mockIssuer.IssueCount()
			initialSecret := getSecret(ctx, k8sClient, ns, targetSecretName)
			initialCredential := string(initialSecret.Data[credentialKey])

			By("triggering re-reconciliation by adding an annotation to the VCR")
			// Use retry.RetryOnConflict because the controller may be actively
			// updating the VCR status, causing resource version conflicts.
			err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
				vcr := getVCRequest(ctx, k8sClient, ns, vcrName)
				if vcr.Annotations == nil {
					vcr.Annotations = make(map[string]string)
				}
				vcr.Annotations["integration-test/trigger-renewal"] = time.Now().Format(time.RFC3339Nano)
				return k8sClient.Update(ctx, vcr)
			})
			Expect(err).NotTo(HaveOccurred(), "Failed to update VCR annotation after retries")

			By("waiting for the credential to be re-issued (issue count increased)")
			Eventually(func() int32 {
				return mockIssuer.IssueCount()
			}, eventuallyTimeout, pollingInterval).Should(BeNumerically(">", countBeforeTrigger),
				"Expected mock issuer to be called again after renewal trigger")

			By("verifying the Secret was updated with a new credential")
			Eventually(func(g Gomega) {
				updatedSecret := getSecret(ctx, k8sClient, ns, targetSecretName)
				newCredential := string(updatedSecret.Data[credentialKey])
				// The new credential should be different (contains different counter).
				g.Expect(newCredential).NotTo(Equal(initialCredential),
					"Credential should have been renewed with a new value")
			}, eventuallyTimeout, pollingInterval).Should(Succeed())

			By("verifying the VCR status reflects the renewal")
			Eventually(func(g Gomega) {
				renewedVCR := getVCRequest(ctx, k8sClient, ns, vcrName)
				g.Expect(renewedVCR.Status.RenewalCount).To(BeNumerically(">=", int32(1)),
					"RenewalCount should be incremented after renewal")
				g.Expect(renewedVCR.Status.LastRenewalTime).NotTo(BeNil(),
					"LastRenewalTime should be set after renewal")
			}, eventuallyTimeout, pollingInterval).Should(Succeed())

			By("verifying the previous credential is preserved for rotation")
			updatedSecret := getSecret(ctx, k8sClient, ns, targetSecretName)
			prevCred, hasPrev := updatedSecret.Data["previousCredential"]
			Expect(hasPrev).To(BeTrue(), "Previous credential should be preserved during rotation")
			Expect(prevCred).NotTo(BeEmpty(), "Previous credential should not be empty")
			// The previousCredential may not equal the initial credential exactly
			// because the controller re-reconciles on status updates, potentially
			// overwriting it multiple times.
		})
	})

	// ---------------------------------------------------------------
	// CR Deletion: Owner references for cleanup
	// ---------------------------------------------------------------
	Context("CR deletion and cleanup", func() {
		It("should set owner references on the target Secret for garbage collection", func() {
			By("setting up the full credential pipeline")
			createAuthSecret(ctx, k8sClient, ns, authSecretName,
				defaultValidClientID, defaultValidClientSecret)
			createCredentialIssuer(ctx, k8sClient, ns, issuerName,
				mockIssuer.URL(), authSecretName)
			waitForIssuerReady(ctx, k8sClient, ns, issuerName)
			createVCRequest(ctx, k8sClient, ns, vcrName,
				issuerName, defaultCredentialType, targetSecretName)
			waitForVCRequestReady(ctx, k8sClient, ns, vcrName)

			By("verifying the target Secret has an owner reference to the VCR")
			vcr := getVCRequest(ctx, k8sClient, ns, vcrName)
			secret := getSecret(ctx, k8sClient, ns, targetSecretName)
			assertSecretHasOwnerReference(secret, vcr.UID, vcr.Name)

			By("verifying the owner reference has blockOwnerDeletion set")
			found := false
			for _, ref := range secret.OwnerReferences {
				if ref.Name == vcr.Name {
					Expect(ref.BlockOwnerDeletion).NotTo(BeNil())
					Expect(*ref.BlockOwnerDeletion).To(BeTrue(),
						"BlockOwnerDeletion should be true for GC cascade")
					found = true
					break
				}
			}
			Expect(found).To(BeTrue())
		})

		It("should handle VCR referencing a non-existent issuer gracefully", func() {
			By("creating a VCR without a matching CredentialIssuer")
			createVCRequest(ctx, k8sClient, ns, vcrName,
				"nonexistent-issuer", defaultCredentialType, targetSecretName)

			By("waiting for the VCR to report IssuerNotFound error")
			waitForVCRequestCondition(ctx, k8sClient, ns, vcrName,
				vcv1alpha1.ConditionTypeError, metav1.ConditionTrue)

			vcr := getVCRequest(ctx, k8sClient, ns, vcrName)
			errorCond := meta.FindStatusCondition(vcr.Status.Conditions, vcv1alpha1.ConditionTypeError)
			Expect(errorCond).NotTo(BeNil())
			Expect(errorCond.Reason).To(Equal(vcv1alpha1.ReasonIssuerNotFound))
		})
	})

	// ---------------------------------------------------------------
	// Credential endpoint failure
	// ---------------------------------------------------------------
	Context("Credential endpoint failure", func() {
		It("should set Error condition when credential endpoint fails", func() {
			By("configuring the mock to fail credential requests")
			mockIssuer.SetFailCredential(true)

			By("setting up the credential pipeline")
			createAuthSecret(ctx, k8sClient, ns, authSecretName,
				defaultValidClientID, defaultValidClientSecret)
			createCredentialIssuer(ctx, k8sClient, ns, issuerName,
				mockIssuer.URL(), authSecretName)
			waitForIssuerReady(ctx, k8sClient, ns, issuerName)
			createVCRequest(ctx, k8sClient, ns, vcrName,
				issuerName, defaultCredentialType, targetSecretName)

			By("waiting for the VCR to enter Error state")
			waitForVCRequestCondition(ctx, k8sClient, ns, vcrName,
				vcv1alpha1.ConditionTypeError, metav1.ConditionTrue)

			By("verifying the error reason is CredentialRequestFailed")
			vcr := getVCRequest(ctx, k8sClient, ns, vcrName)
			errorCond := meta.FindStatusCondition(vcr.Status.Conditions, vcv1alpha1.ConditionTypeError)
			Expect(errorCond).NotTo(BeNil())
			Expect(errorCond.Reason).To(Equal(vcv1alpha1.ReasonCredentialRequestFailed))
		})
	})

	// ---------------------------------------------------------------
	// Token endpoint forced failure
	// ---------------------------------------------------------------
	Context("Token endpoint forced failure", func() {
		It("should set Error condition when token endpoint always fails", func() {
			By("configuring the mock to always fail token requests")
			mockIssuer.SetFailToken(true)

			By("setting up the credential pipeline with valid credentials")
			createAuthSecret(ctx, k8sClient, ns, authSecretName,
				defaultValidClientID, defaultValidClientSecret)
			createCredentialIssuer(ctx, k8sClient, ns, issuerName,
				mockIssuer.URL(), authSecretName)
			waitForIssuerReady(ctx, k8sClient, ns, issuerName)
			createVCRequest(ctx, k8sClient, ns, vcrName,
				issuerName, defaultCredentialType, targetSecretName)

			By("waiting for the VCR to enter Error state")
			waitForVCRequestCondition(ctx, k8sClient, ns, vcrName,
				vcv1alpha1.ConditionTypeError, metav1.ConditionTrue)

			By("verifying the error is TokenRequestFailed")
			vcr := getVCRequest(ctx, k8sClient, ns, vcrName)
			errorCond := meta.FindStatusCondition(vcr.Status.Conditions, vcv1alpha1.ConditionTypeError)
			Expect(errorCond).NotTo(BeNil())
			Expect(errorCond.Reason).To(Equal(vcv1alpha1.ReasonTokenRequestFailed))
		})
	})

	// ---------------------------------------------------------------
	// Recovery: Issuer becomes available after initial failure
	// ---------------------------------------------------------------
	Context("Recovery after issuer failure", func() {
		It("should recover when a failed token endpoint starts working", func() {
			By("configuring the mock to fail token requests initially")
			mockIssuer.SetFailToken(true)

			By("setting up the credential pipeline")
			createAuthSecret(ctx, k8sClient, ns, authSecretName,
				defaultValidClientID, defaultValidClientSecret)
			createCredentialIssuer(ctx, k8sClient, ns, issuerName,
				mockIssuer.URL(), authSecretName)
			waitForIssuerReady(ctx, k8sClient, ns, issuerName)
			createVCRequest(ctx, k8sClient, ns, vcrName,
				issuerName, defaultCredentialType, targetSecretName)

			By("waiting for the initial Error condition")
			waitForVCRequestCondition(ctx, k8sClient, ns, vcrName,
				vcv1alpha1.ConditionTypeError, metav1.ConditionTrue)

			By("fixing the token endpoint")
			mockIssuer.SetFailToken(false)

			By("triggering re-reconciliation by updating the VCR annotation")
			// Use retry.RetryOnConflict because the controller may be actively
			// updating the VCR status, causing resource version conflicts.
			err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
				vcr := &vcv1alpha1.VerifiableCredentialRequest{}
				if getErr := k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: vcrName}, vcr); getErr != nil {
					return getErr
				}
				if vcr.Annotations == nil {
					vcr.Annotations = make(map[string]string)
				}
				vcr.Annotations["integration-test/retry"] = time.Now().Format(time.RFC3339Nano)
				return k8sClient.Update(ctx, vcr)
			})
			Expect(err).NotTo(HaveOccurred(), "Failed to update VCR annotation after retries")

			By("waiting for the VCR to recover and become Ready")
			waitForVCRequestReady(ctx, k8sClient, ns, vcrName)

			By("verifying the credential was stored after recovery")
			assertSecretHasCredential(ctx, k8sClient, ns, targetSecretName, credentialKey)

			By("verifying the Error condition was cleared")
			recoveredVCR := getVCRequest(ctx, k8sClient, ns, vcrName)
			errorCond := meta.FindStatusCondition(recoveredVCR.Status.Conditions, vcv1alpha1.ConditionTypeError)
			Expect(errorCond).To(BeNil(), "Error condition should be cleared after successful recovery")
		})
	})
})

// decodeJWTPayload extracts and decodes the payload segment of a
// compact-serialized JWT for test assertions. It returns the payload
// claims as a map. Fails the test if the JWT is malformed.
func decodeJWTPayload(jwtStr string) map[string]any {
	segments := strings.Split(jwtStr, ".")
	Expect(segments).To(HaveLen(jwtSegmentCount), "JWT should have 3 segments")

	// Decode the payload (segment at index 1) using base64url without padding.
	payloadBytes, err := base64.RawURLEncoding.DecodeString(segments[1])
	Expect(err).NotTo(HaveOccurred(), "Failed to decode JWT payload segment")

	var payload map[string]any
	Expect(json.Unmarshal(payloadBytes, &payload)).To(Succeed(), "Failed to parse JWT payload JSON")
	return payload
}
