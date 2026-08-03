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

// DefaultIssuerType is the default value for IssuerType when not specified.
const DefaultIssuerType = "generic"

// CredentialIssuerSpec configures an OID4VCI credential issuer.
// The operator uses this configuration to discover issuer metadata,
// authenticate to the token endpoint, and request credentials.
type CredentialIssuerSpec struct {
	// IssuerURL is the base URL of the OID4VCI credential issuer.
	// The operator discovers metadata at {IssuerURL}/.well-known/openid-credential-issuer.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Pattern=`^https?://`
	IssuerURL string `json:"issuerURL"`

	// IssuerType identifies the issuer implementation (e.g., "keycloak", "generic").
	// Different issuer types may require specific handling during credential issuance.
	// Defaults to "generic" if not specified.
	// +kubebuilder:validation:Enum=generic;keycloak
	// +kubebuilder:default=generic
	// +optional
	IssuerType string `json:"issuerType,omitempty"`

	// AuthSecretRef references a Kubernetes Secret in the same namespace containing
	// authentication credentials for the token endpoint.
	// The Secret must contain at least "client_id" and "client_secret" keys
	// for client_credentials grant, or a "pre_authorized_code" key for the
	// pre-authorized code flow.
	AuthSecretRef SecretReference `json:"authSecretRef"`

	// TokenURL optionally overrides the token endpoint URL discovered from
	// issuer metadata. Use this when the issuer's metadata does not advertise
	// the correct token endpoint or when a custom endpoint is required.
	// +kubebuilder:validation:Pattern=`^https?://`
	// +optional
	TokenURL string `json:"tokenURL,omitempty"`
}

// CredentialIssuerStatus defines the observed state of a CredentialIssuer.
// It contains the discovered metadata endpoints and standard Kubernetes conditions.
type CredentialIssuerStatus struct {
	// IssuerIdentifier is the credential_issuer value from the OID4VCI metadata.
	// This is the canonical issuer identifier used as the audience in proof JWTs
	// and may differ from spec.issuerURL when the issuer is accessed via an
	// internal URL but identifies itself with an external URL.
	// +optional
	IssuerIdentifier string `json:"issuerIdentifier,omitempty"`

	// CredentialEndpoint is the credential endpoint URL discovered from
	// the issuer's OID4VCI metadata.
	// +optional
	CredentialEndpoint string `json:"credentialEndpoint,omitempty"`

	// NonceEndpoint is the nonce endpoint URL discovered from the issuer's
	// OID4VCI metadata (draft 15+/Keycloak 26.x). When present, the operator
	// fetches a fresh nonce from this endpoint for proof-of-possession JWTs.
	// +optional
	NonceEndpoint string `json:"nonceEndpoint,omitempty"`

	// TokenEndpoint is the token endpoint URL discovered from
	// the issuer's OID4VCI metadata or overridden by spec.tokenURL.
	// +optional
	TokenEndpoint string `json:"tokenEndpoint,omitempty"`

	// SupportedCredentialTypes lists the credential type identifiers
	// advertised by the issuer in credential_configurations_supported.
	// +optional
	SupportedCredentialTypes []string `json:"supportedCredentialTypes,omitempty"`

	// LastMetadataFetchTime is the timestamp of the last successful
	// metadata discovery from the issuer.
	// +optional
	LastMetadataFetchTime *metav1.Time `json:"lastMetadataFetchTime,omitempty"`

	// Conditions represent the current state of the CredentialIssuer resource.
	//
	// Condition types include:
	// - "Ready": the issuer metadata has been successfully discovered and the auth secret is valid.
	// - "Error": a non-transient error occurred (e.g., invalid issuer URL, missing auth secret).
	//
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=ciss
// +kubebuilder:printcolumn:name="Issuer URL",type=string,JSONPath=`.spec.issuerURL`,description="The URL of the OID4VCI credential issuer"
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.spec.issuerType`,description="The issuer implementation type"
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`,description="Whether the issuer is ready"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// CredentialIssuer configures an OID4VCI credential issuer that the operator
// can use to obtain Verifiable Credentials. It discovers issuer metadata,
// validates connectivity, and caches endpoint information for use by
// VerifiableCredentialRequest resources.
type CredentialIssuer struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired configuration for the credential issuer.
	// +required
	Spec CredentialIssuerSpec `json:"spec"`

	// status defines the observed state of the credential issuer.
	// +optional
	Status CredentialIssuerStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// CredentialIssuerList contains a list of CredentialIssuer resources.
type CredentialIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []CredentialIssuer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&CredentialIssuer{}, &CredentialIssuerList{})
}
