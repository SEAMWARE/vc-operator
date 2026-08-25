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
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	vcv1alpha1 "github.com/SEAMWARE/vc-operator/api/v1alpha1"
)

// Test timeout and polling constants for Eventually/Consistently assertions.
const (
	// eventuallyTimeout is the maximum time to wait for an async condition.
	eventuallyTimeout = 30 * time.Second

	// pollingInterval is the interval between condition checks.
	pollingInterval = 250 * time.Millisecond

	// consistentlyDuration is how long a condition must remain true.
	consistentlyDuration = 3 * time.Second

	// randomSuffixLength is the number of random bytes used for namespace uniqueness.
	randomSuffixLength = 4
)

// generateRandomSuffix returns a short hex string for generating unique
// namespace names, preventing test interference across parallel runs.
func generateRandomSuffix() string {
	b := make([]byte, randomSuffixLength)
	_, err := rand.Read(b)
	if err != nil {
		// Fallback to timestamp if crypto/rand fails.
		return fmt.Sprintf("%x", time.Now().UnixNano()%0xFFFF)
	}
	return hex.EncodeToString(b)
}

// createNamespace creates a new Kubernetes namespace with the given name.
// It fails the test if the namespace cannot be created.
func createNamespace(ctx context.Context, c client.Client, name string) {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
	Expect(c.Create(ctx, ns)).To(Succeed(), "Failed to create namespace %s", name)
}

// deleteNamespace deletes a Kubernetes namespace by name. Errors are
// ignored since envtest cleanup is best-effort.
func deleteNamespace(ctx context.Context, c client.Client, name string) {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
	_ = c.Delete(ctx, ns)
}

// createAuthSecret creates a Kubernetes Secret containing OAuth 2.0
// client credentials (client_id and client_secret) for use as an
// authentication reference in a CredentialIssuer.
func createAuthSecret(ctx context.Context, c client.Client, namespace, name, clientID, clientSecret string) *corev1.Secret {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"client_id":     []byte(clientID),
			"client_secret": []byte(clientSecret),
		},
	}
	Expect(c.Create(ctx, secret)).To(Succeed(), "Failed to create auth Secret %s/%s", namespace, name)
	return secret
}

// createCredentialIssuer creates a CredentialIssuer CR pointing to the
// given issuer URL with a reference to the specified auth Secret.
func createCredentialIssuer(
	ctx context.Context,
	c client.Client,
	namespace, name, issuerURL, authSecretName string,
) *vcv1alpha1.CredentialIssuer {
	issuer := &vcv1alpha1.CredentialIssuer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: vcv1alpha1.CredentialIssuerSpec{
			IssuerURL:  issuerURL,
			IssuerType: "keycloak",
			AuthSecretRef: vcv1alpha1.SecretReference{
				Name: authSecretName,
			},
		},
	}
	Expect(c.Create(ctx, issuer)).To(Succeed(), "Failed to create CredentialIssuer %s/%s", namespace, name)
	return issuer
}

// createVCRequest creates a VerifiableCredentialRequest CR referencing
// the given CredentialIssuer and targeting the specified Secret name
// for credential storage.
func createVCRequest(
	ctx context.Context,
	c client.Client,
	namespace, name, issuerRefName, credentialType, targetSecretName string,
) *vcv1alpha1.VerifiableCredentialRequest {
	vcr := &vcv1alpha1.VerifiableCredentialRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: vcv1alpha1.VerifiableCredentialRequestSpec{
			IssuerRef: vcv1alpha1.LocalObjectReference{
				Name: issuerRefName,
			},
			CredentialType: credentialType,
			Format:         "jwt_vc_json",
			StorageType:    "kubernetes",
			TargetSecretRef: vcv1alpha1.TargetSecretReference{
				Name: targetSecretName,
				Key:  "credential",
			},
		},
	}
	Expect(c.Create(ctx, vcr)).To(Succeed(), "Failed to create VerifiableCredentialRequest %s/%s", namespace, name)
	return vcr
}

// createVCRequestWithRenewBefore creates a VerifiableCredentialRequest
// with a custom renewBefore duration, used for testing renewal behavior.
func createVCRequestWithRenewBefore(
	ctx context.Context,
	c client.Client,
	namespace, name, issuerRefName, credentialType, targetSecretName string,
	renewBefore time.Duration,
) *vcv1alpha1.VerifiableCredentialRequest {
	vcr := &vcv1alpha1.VerifiableCredentialRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: vcv1alpha1.VerifiableCredentialRequestSpec{
			IssuerRef: vcv1alpha1.LocalObjectReference{
				Name: issuerRefName,
			},
			CredentialType: credentialType,
			Format:         "jwt_vc_json",
			StorageType:    "kubernetes",
			TargetSecretRef: vcv1alpha1.TargetSecretReference{
				Name: targetSecretName,
				Key:  "credential",
			},
			RenewBefore: &metav1.Duration{Duration: renewBefore},
		},
	}
	Expect(c.Create(ctx, vcr)).To(Succeed(), "Failed to create VerifiableCredentialRequest %s/%s", namespace, name)
	return vcr
}

// waitForIssuerReady waits for a CredentialIssuer to reach the Ready
// condition with status True. Fails the test if the condition is not
// met within eventuallyTimeout.
func waitForIssuerReady(ctx context.Context, c client.Client, namespace, name string) {
	By(fmt.Sprintf("waiting for CredentialIssuer %s/%s to become Ready", namespace, name))
	Eventually(func(g Gomega) {
		issuer := &vcv1alpha1.CredentialIssuer{}
		g.Expect(c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, issuer)).To(Succeed())
		readyCond := meta.FindStatusCondition(issuer.Status.Conditions, vcv1alpha1.ConditionTypeReady)
		g.Expect(readyCond).NotTo(BeNil(), "Ready condition not found")
		g.Expect(readyCond.Status).To(Equal(metav1.ConditionTrue), "CredentialIssuer not Ready: %s", readyCond.Message)
	}, eventuallyTimeout, pollingInterval).Should(Succeed())
}

// waitForVCRequestReady waits for a VerifiableCredentialRequest to reach
// the Ready condition with status True. Fails the test if the condition
// is not met within eventuallyTimeout.
func waitForVCRequestReady(ctx context.Context, c client.Client, namespace, name string) {
	By(fmt.Sprintf("waiting for VerifiableCredentialRequest %s/%s to become Ready", namespace, name))
	Eventually(func(g Gomega) {
		vcr := &vcv1alpha1.VerifiableCredentialRequest{}
		g.Expect(c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, vcr)).To(Succeed())
		readyCond := meta.FindStatusCondition(vcr.Status.Conditions, vcv1alpha1.ConditionTypeReady)
		g.Expect(readyCond).NotTo(BeNil(), "Ready condition not found")
		g.Expect(readyCond.Status).To(Equal(metav1.ConditionTrue), "VCR not Ready: %s", readyCond.Message)
	}, eventuallyTimeout, pollingInterval).Should(Succeed())
}

// waitForVCRequestCondition waits for a VerifiableCredentialRequest to
// have the specified condition type with the expected status value.
func waitForVCRequestCondition(
	ctx context.Context,
	c client.Client,
	namespace, name string,
	conditionType string,
	expectedStatus metav1.ConditionStatus,
) {
	By(fmt.Sprintf("waiting for VCR %s/%s condition %s=%s", namespace, name, conditionType, expectedStatus))
	Eventually(func(g Gomega) {
		vcr := &vcv1alpha1.VerifiableCredentialRequest{}
		g.Expect(c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, vcr)).To(Succeed())
		cond := meta.FindStatusCondition(vcr.Status.Conditions, conditionType)
		g.Expect(cond).NotTo(BeNil(), "Condition %s not found on VCR", conditionType)
		g.Expect(cond.Status).To(Equal(expectedStatus),
			"Condition %s expected %s but got %s: %s", conditionType, expectedStatus, cond.Status, cond.Message)
	}, eventuallyTimeout, pollingInterval).Should(Succeed())
}

// waitForIssuerCondition waits for a CredentialIssuer to have the
// specified condition type with the expected status value.
func waitForIssuerCondition(
	ctx context.Context,
	c client.Client,
	namespace, name string,
	conditionType string,
	expectedStatus metav1.ConditionStatus,
) {
	By(fmt.Sprintf("waiting for issuer %s/%s condition %s=%s", namespace, name, conditionType, expectedStatus))
	Eventually(func(g Gomega) {
		issuer := &vcv1alpha1.CredentialIssuer{}
		g.Expect(c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, issuer)).To(Succeed())
		cond := meta.FindStatusCondition(issuer.Status.Conditions, conditionType)
		g.Expect(cond).NotTo(BeNil(), "Condition %s not found on issuer", conditionType)
		g.Expect(cond.Status).To(Equal(expectedStatus),
			"Condition %s expected %s but got %s: %s", conditionType, expectedStatus, cond.Status, cond.Message)
	}, eventuallyTimeout, pollingInterval).Should(Succeed())
}

// getSecret fetches a Kubernetes Secret by namespace and name. Fails
// the test if the Secret cannot be retrieved.
func getSecret(ctx context.Context, c client.Client, namespace, name string) *corev1.Secret {
	secret := &corev1.Secret{}
	Expect(c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, secret)).
		To(Succeed(), "Failed to get Secret %s/%s", namespace, name)
	return secret
}

// getVCRequest fetches a VerifiableCredentialRequest by namespace and
// name. Fails the test if the CR cannot be retrieved.
func getVCRequest(ctx context.Context, c client.Client, namespace, name string) *vcv1alpha1.VerifiableCredentialRequest {
	vcr := &vcv1alpha1.VerifiableCredentialRequest{}
	Expect(c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, vcr)).
		To(Succeed(), "Failed to get VCR %s/%s", namespace, name)
	return vcr
}

// getCredentialIssuer fetches a CredentialIssuer by namespace and name.
// Fails the test if the CR cannot be retrieved.
func getCredentialIssuer(ctx context.Context, c client.Client, namespace, name string) *vcv1alpha1.CredentialIssuer {
	issuer := &vcv1alpha1.CredentialIssuer{}
	Expect(c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, issuer)).
		To(Succeed(), "Failed to get CredentialIssuer %s/%s", namespace, name)
	return issuer
}

// assertSecretHasCredential verifies that a Secret exists, contains a
// non-empty credential under the specified key, has the expected format
// metadata, and carries the vc-operator managed-by label.
func assertSecretHasCredential(ctx context.Context, c client.Client, namespace, secretName, credentialKey string) *corev1.Secret {
	By(fmt.Sprintf("verifying Secret %s/%s contains credential data", namespace, secretName))
	secret := getSecret(ctx, c, namespace, secretName)

	// Verify the credential data is present.
	credData, ok := secret.Data[credentialKey]
	Expect(ok).To(BeTrue(), "Secret missing credential key %q", credentialKey)
	Expect(credData).NotTo(BeEmpty(), "Credential data is empty")

	// Verify the format metadata key is present.
	formatData, ok := secret.Data["format"]
	Expect(ok).To(BeTrue(), "Secret missing format key")
	Expect(string(formatData)).To(Equal(defaultCredentialFormat))

	// Verify the managed-by label.
	Expect(secret.Labels).To(HaveKeyWithValue("app.kubernetes.io/managed-by", "vc-operator"))
	Expect(secret.Labels).To(HaveKeyWithValue("app.kubernetes.io/component", "credential"))

	return secret
}

// assertSecretHasOwnerReference verifies that a Secret has an owner
// reference pointing to the specified VerifiableCredentialRequest UID.
// This ensures the Secret will be garbage-collected when the VCR is
// deleted in a production cluster.
func assertSecretHasOwnerReference(secret *corev1.Secret, ownerUID types.UID, ownerName string) {
	By(fmt.Sprintf("verifying Secret %s/%s has owner reference to %s", secret.Namespace, secret.Name, ownerName))
	Expect(secret.OwnerReferences).NotTo(BeEmpty(), "Secret has no owner references")

	found := false
	for _, ref := range secret.OwnerReferences {
		if ref.UID == ownerUID && ref.Name == ownerName {
			Expect(ref.Kind).To(Equal("VerifiableCredentialRequest"))
			Expect(ref.APIVersion).To(ContainSubstring("vc.vc-operator.io"))
			if ref.Controller != nil {
				Expect(*ref.Controller).To(BeTrue())
			}
			found = true
			break
		}
	}
	Expect(found).To(BeTrue(), "Owner reference for %s not found on Secret", ownerName)
}
