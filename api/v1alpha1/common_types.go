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

// Condition type constants define the standard condition types used across
// CredentialIssuer and VerifiableCredentialRequest status.
const (
	// ConditionTypeReady indicates that the resource is fully operational.
	// For CredentialIssuer: metadata has been successfully discovered.
	// For VerifiableCredentialRequest: a valid credential has been obtained and stored.
	ConditionTypeReady = "Ready"

	// ConditionTypeCredentialIssued indicates that a credential has been
	// successfully obtained from the issuer and stored in the target backend.
	// Applies to VerifiableCredentialRequest only.
	ConditionTypeCredentialIssued = "CredentialIssued"

	// ConditionTypeRenewalScheduled indicates that automatic renewal has
	// been scheduled for the credential before its expiry.
	// Applies to VerifiableCredentialRequest only.
	ConditionTypeRenewalScheduled = "RenewalScheduled"

	// ConditionTypeError indicates that a non-transient error has occurred
	// that requires user intervention to resolve.
	ConditionTypeError = "Error"
)

// Condition reason constants provide machine-readable reasons for condition
// state transitions.
const (
	// ReasonMetadataDiscovered indicates that OID4VCI metadata was
	// successfully fetched from the issuer.
	ReasonMetadataDiscovered = "MetadataDiscovered"

	// ReasonMetadataFetchFailed indicates that the operator could not
	// fetch OID4VCI metadata from the issuer URL.
	ReasonMetadataFetchFailed = "MetadataFetchFailed"

	// ReasonAuthSecretNotFound indicates that the referenced
	// authentication Secret does not exist.
	ReasonAuthSecretNotFound = "AuthSecretNotFound"

	// ReasonAuthSecretInvalid indicates that the referenced
	// authentication Secret exists but is missing required keys.
	ReasonAuthSecretInvalid = "AuthSecretInvalid"

	// ReasonIssuerNotReady indicates that the referenced CredentialIssuer
	// is not in a Ready state.
	ReasonIssuerNotReady = "IssuerNotReady"

	// ReasonIssuerNotFound indicates that the referenced CredentialIssuer
	// does not exist in the same namespace.
	ReasonIssuerNotFound = "IssuerNotFound"

	// ReasonCredentialObtained indicates that a credential was
	// successfully obtained from the issuer.
	ReasonCredentialObtained = "CredentialObtained"

	// ReasonCredentialRequestFailed indicates that the credential
	// request to the issuer failed.
	ReasonCredentialRequestFailed = "CredentialRequestFailed"

	// ReasonRenewalScheduled indicates that the next credential renewal
	// has been scheduled.
	ReasonRenewalScheduled = "RenewalScheduled"

	// ReasonTokenRequestFailed indicates that the access token request
	// to the token endpoint failed.
	ReasonTokenRequestFailed = "TokenRequestFailed"

	// ReasonStorageFailed indicates that storing the credential in the
	// target backend failed.
	ReasonStorageFailed = "StorageFailed"

	// ReasonHolderKeyInvalid indicates that the referenced holder key
	// Secret is missing, contains invalid key data, or holderDID is set
	// without holderKeyRef.
	ReasonHolderKeyInvalid = "HolderKeyInvalid"

	// ReasonStoredCredentialMissing indicates that a previously issued
	// credential is no longer present in the storage backend (for example,
	// the target Secret was deleted or emptied out-of-band), which triggers
	// an immediate re-issuance.
	ReasonStoredCredentialMissing = "StoredCredentialMissing"
)

// SecretReference is a reference to a Kubernetes Secret in the same namespace.
type SecretReference struct {
	// Name is the name of the Secret.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// LocalObjectReference is a reference to a resource in the same namespace.
type LocalObjectReference struct {
	// Name is the name of the referenced resource.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// TargetSecretReference specifies where the obtained credential should be stored
// in the storage backend. For the "kubernetes" storage type, this identifies
// the target Kubernetes Secret.
type TargetSecretReference struct {
	// Name is the name of the target resource in the storage backend
	// (e.g., the Kubernetes Secret name).
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Key is the data key within the target resource under which the
	// credential will be stored. Defaults to "credential".
	// +kubebuilder:default=credential
	// +optional
	Key string `json:"key,omitempty"`
}
