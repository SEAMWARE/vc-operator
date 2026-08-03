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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Default values for VerifiableCredentialRequest fields.
const (
	// DefaultCredentialFormat is the default credential format when not specified.
	DefaultCredentialFormat = "jwt_vc_json"

	// DefaultStorageType is the default storage backend when not specified.
	DefaultStorageType = "kubernetes"

	// DefaultRenewBeforeDuration is the default duration string before expiry
	// at which renewal is attempted, used when renewBefore is not specified.
	DefaultRenewBeforeDuration = "5m"
)

// VerifiableCredentialRequestSpec defines the desired credential to obtain
// from an OID4VCI issuer and how it should be stored.
type VerifiableCredentialRequestSpec struct {
	// IssuerRef references a CredentialIssuer resource in the same namespace.
	// The referenced issuer must be in a Ready state before credentials
	// can be obtained.
	IssuerRef LocalObjectReference `json:"issuerRef"`

	// CredentialType is the type identifier for the credential to request,
	// as advertised in the issuer's credential_configurations_supported metadata.
	// +kubebuilder:validation:MinLength=1
	CredentialType string `json:"credentialType"`

	// Format specifies the credential format to request from the issuer
	// (e.g., "jwt_vc_json", "ldp_vc"). Defaults to "jwt_vc_json".
	// +kubebuilder:validation:Enum=jwt_vc_json;ldp_vc;jwt_vc;vc+sd-jwt
	// +kubebuilder:default=jwt_vc_json
	// +optional
	Format string `json:"format,omitempty"`

	// StorageType selects the credential storage backend.
	// Supported values: "kubernetes" (default). Future backends may include "vault".
	// +kubebuilder:validation:Enum=kubernetes
	// +kubebuilder:default=kubernetes
	// +optional
	StorageType string `json:"storageType,omitempty"`

	// TargetSecretRef specifies the target reference in the storage backend
	// where the obtained credential will be stored (e.g., a Kubernetes Secret name).
	TargetSecretRef TargetSecretReference `json:"targetSecretRef"`

	// RenewBefore specifies how long before credential expiry the operator
	// should attempt renewal. If not specified, defaults to 5 minutes.
	// +optional
	RenewBefore *metav1.Duration `json:"renewBefore,omitempty"`

	// AdditionalClaims allows specifying extra claims to include in the
	// credential request. These are issuer-specific and passed through
	// as-is in the credential request body.
	// +optional
	AdditionalClaims map[string]string `json:"additionalClaims,omitempty"`

	// HolderKeyRef optionally references a Kubernetes Secret containing the
	// holder's ECDSA P-256 private key in PEM format (expected data keys:
	// "key.pem" or "tls.key"). When set, the operator uses this key to sign
	// the proof-of-possession JWT in the credential request, causing the
	// issuer to bind the credential to this key's identity.
	// When omitted, no proof-of-possession is included in the request.
	// +optional
	HolderKeyRef *SecretReference `json:"holderKeyRef,omitempty"`

	// HolderDID optionally specifies a DID URL to include as the "kid" header
	// in the proof-of-possession JWT instead of embedding the full JWK.
	// The DID must resolve to the public key corresponding to the private
	// key referenced by HolderKeyRef.
	// Requires HolderKeyRef to be set.
	// +optional
	HolderDID string `json:"holderDID,omitempty"`
}

// VerifiableCredentialRequestStatus defines the observed state of a
// VerifiableCredentialRequest. It tracks the credential lifecycle including
// issuance, renewal, and expiry information.
type VerifiableCredentialRequestStatus struct {
	// CredentialExpiryTime is the expiry time of the currently stored credential,
	// extracted from the credential's claims (e.g., the "exp" JWT claim).
	// +optional
	CredentialExpiryTime *metav1.Time `json:"credentialExpiryTime,omitempty"`

	// LastIssuanceTime is the timestamp of the last successful credential issuance.
	// +optional
	LastIssuanceTime *metav1.Time `json:"lastIssuanceTime,omitempty"`

	// LastRenewalTime is the timestamp of the last successful credential renewal.
	// This differs from LastIssuanceTime in that it tracks only renewals,
	// not the initial issuance.
	// +optional
	LastRenewalTime *metav1.Time `json:"lastRenewalTime,omitempty"`

	// NextRenewalTime is the scheduled time for the next credential renewal attempt.
	// Computed as credentialExpiryTime - renewBefore.
	// +optional
	NextRenewalTime *metav1.Time `json:"nextRenewalTime,omitempty"`

	// RenewalCount tracks the total number of times this credential has been
	// successfully renewed. This counter is monotonically increasing and is
	// useful for observability and auditing.
	// +optional
	RenewalCount int32 `json:"renewalCount,omitempty"`

	// CredentialFormat is the format of the stored credential (e.g., "jwt_vc_json").
	// +optional
	CredentialFormat string `json:"credentialFormat,omitempty"`

	// Conditions represent the current state of the VerifiableCredentialRequest resource.
	//
	// Condition types include:
	// - "Ready": a valid credential has been obtained and stored.
	// - "CredentialIssued": a credential was successfully obtained from the issuer.
	// - "RenewalScheduled": automatic renewal has been scheduled before expiry.
	// - "Error": a non-transient error occurred during credential acquisition.
	//
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=vcr
// +kubebuilder:printcolumn:name="Issuer",type=string,JSONPath=`.spec.issuerRef.name`,description="The referenced CredentialIssuer"
// +kubebuilder:printcolumn:name="Credential Type",type=string,JSONPath=`.spec.credentialType`,description="The requested credential type"
// +kubebuilder:printcolumn:name="Format",type=string,JSONPath=`.spec.format`,description="The credential format"
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`,description="Whether a valid credential is stored"
// +kubebuilder:printcolumn:name="Expiry",type=date,JSONPath=`.status.credentialExpiryTime`,description="Credential expiry time"
// +kubebuilder:printcolumn:name="Renewals",type=integer,JSONPath=`.status.renewalCount`,description="Number of successful renewals"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// VerifiableCredentialRequest declares a Verifiable Credential that a service
// needs. The operator obtains the credential from the referenced CredentialIssuer
// via the OID4VCI protocol, stores it in the configured storage backend, and
// automatically renews it before expiry.
type VerifiableCredentialRequest struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired credential and its storage configuration.
	// +required
	Spec VerifiableCredentialRequestSpec `json:"spec"`

	// status defines the observed state of the credential request.
	// +optional
	Status VerifiableCredentialRequestStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// VerifiableCredentialRequestList contains a list of VerifiableCredentialRequest resources.
type VerifiableCredentialRequestList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []VerifiableCredentialRequest `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VerifiableCredentialRequest{}, &VerifiableCredentialRequestList{})
}
