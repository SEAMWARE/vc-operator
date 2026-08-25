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
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	vcv1alpha1 "github.com/SEAMWARE/vc-operator/api/v1alpha1"
	"github.com/SEAMWARE/vc-operator/internal/oid4vci"
)

const (
	// MetadataRefreshInterval is the default interval between periodic OID4VCI
	// metadata refresh cycles for a healthy CredentialIssuer.
	MetadataRefreshInterval = 30 * time.Minute

	// DefaultErrorRequeueInterval is the default interval to wait before retrying
	// reconciliation after a non-transient configuration error (e.g., missing
	// auth Secret). Can be overridden per-reconciler via the ErrorRequeueInterval
	// field.
	DefaultErrorRequeueInterval = 1 * time.Minute

	// AuthSecretKeyClientID is the expected data key in the authentication Secret
	// containing the OAuth 2.0 client identifier.
	AuthSecretKeyClientID = "client_id"

	// AuthSecretKeyClientSecret is the expected data key in the authentication Secret
	// containing the OAuth 2.0 client secret.
	AuthSecretKeyClientSecret = "client_secret"

	// AuthSecretKeyPreAuthorizedCode is the expected data key in the authentication
	// Secret containing the OID4VCI pre-authorized code.
	AuthSecretKeyPreAuthorizedCode = "pre_authorized_code"

	// ActionValidateAuthSecret is the event action recorded when the controller
	// validates the authentication Secret referenced by a CredentialIssuer.
	ActionValidateAuthSecret = "ValidateAuthSecret"

	// ActionDiscoverMetadata is the event action recorded when the controller
	// performs OID4VCI metadata discovery for a CredentialIssuer.
	ActionDiscoverMetadata = "DiscoverMetadata"
)

// CredentialIssuerReconciler reconciles CredentialIssuer resources.
// It validates issuer connectivity by fetching OID4VCI metadata, verifies
// that the referenced authentication Secret exists and has required keys,
// and caches discovered endpoint information in the CR status for consumption
// by VerifiableCredentialRequest reconcilers.
type CredentialIssuerReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	OID4VCIClient oid4vci.Client
	EventRecorder events.EventRecorder

	// ErrorRequeueInterval overrides the default interval between retries after
	// a non-transient configuration error. When zero, DefaultErrorRequeueInterval
	// is used.
	ErrorRequeueInterval time.Duration
}

// errorRequeueInterval returns the configured error requeue interval,
// falling back to DefaultErrorRequeueInterval when not set.
func (r *CredentialIssuerReconciler) errorRequeueInterval() time.Duration {
	if r.ErrorRequeueInterval > 0 {
		return r.ErrorRequeueInterval
	}
	return DefaultErrorRequeueInterval
}

// +kubebuilder:rbac:groups=vc.vc-operator.io,resources=credentialissuers,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=vc.vc-operator.io,resources=credentialissuers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=vc.vc-operator.io,resources=credentialissuers/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch

// Reconcile performs a single reconciliation cycle for a CredentialIssuer resource.
// It validates the referenced auth Secret, discovers OID4VCI metadata from the
// issuer URL, updates the CR status with discovered endpoints, and schedules
// periodic metadata refresh.
//
// The reconciliation flow:
//  1. Fetch the CredentialIssuer CR (return if deleted).
//  2. Validate the referenced auth Secret exists and has required keys.
//  3. Discover OID4VCI metadata from the issuer URL.
//  4. Update status with discovered endpoints and set Ready condition.
//  5. Requeue after MetadataRefreshInterval for periodic refresh.
func (r *CredentialIssuerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	log.V(1).Info("Reconciling CredentialIssuer", "name", req.NamespacedName)

	// Fetch the CredentialIssuer resource.
	var issuer vcv1alpha1.CredentialIssuer
	if err := r.Get(ctx, req.NamespacedName, &issuer); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("CredentialIssuer not found; ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to fetch CredentialIssuer")
		return ctrl.Result{}, err
	}

	// Validate the referenced auth Secret exists and has required keys.
	// On failure, validateAuthSecret updates the CR status and records events.
	if err := r.validateAuthSecret(ctx, &issuer); err != nil {
		// Auth validation errors are configuration issues; requeue after a fixed
		// interval rather than exponential backoff, since there is no benefit to
		// backing off on user-correctable errors.
		return ctrl.Result{RequeueAfter: r.errorRequeueInterval()}, nil
	}

	// Discover OID4VCI metadata from the issuer URL.
	metadata, err := r.OID4VCIClient.DiscoverMetadata(ctx, issuer.Spec.IssuerURL)
	if err != nil {
		return r.handleMetadataError(ctx, &issuer, err)
	}

	// Update status with discovered metadata and set Ready condition.
	return r.handleMetadataSuccess(ctx, &issuer, metadata)
}

// validateAuthSecret checks that the referenced authentication Secret exists
// and contains the required keys for at least one supported grant type.
//
// The Secret must contain either:
//   - "client_id" and "client_secret" keys (for client_credentials grant), or
//   - "pre_authorized_code" key (for pre-authorized code flow).
//
// On validation failure, it updates the CredentialIssuer status conditions,
// records a Kubernetes event, and returns an error.
func (r *CredentialIssuerReconciler) validateAuthSecret(ctx context.Context, issuer *vcv1alpha1.CredentialIssuer) error {
	log := logf.FromContext(ctx)

	secretKey := types.NamespacedName{
		Name:      issuer.Spec.AuthSecretRef.Name,
		Namespace: issuer.Namespace,
	}

	var secret corev1.Secret
	if err := r.Get(ctx, secretKey, &secret); err != nil {
		if apierrors.IsNotFound(err) {
			msg := fmt.Sprintf("Auth Secret %q not found in namespace %q", secretKey.Name, secretKey.Namespace)
			log.Info("Auth secret not found", "secret", secretKey)
			r.EventRecorder.Eventf(issuer, nil, corev1.EventTypeWarning, vcv1alpha1.ReasonAuthSecretNotFound, ActionValidateAuthSecret, msg)
			if statusErr := r.setErrorStatus(ctx, issuer, vcv1alpha1.ReasonAuthSecretNotFound, msg); statusErr != nil {
				return statusErr
			}
			return fmt.Errorf("auth secret not found: %s/%s", secretKey.Namespace, secretKey.Name)
		}
		log.Error(err, "Failed to fetch auth Secret", "secret", secretKey)
		return err
	}

	// Validate that the Secret contains required keys for at least one grant type.
	hasClientCredentials := hasSecretKey(secret.Data, AuthSecretKeyClientID) &&
		hasSecretKey(secret.Data, AuthSecretKeyClientSecret)
	hasPreAuthorizedCode := hasSecretKey(secret.Data, AuthSecretKeyPreAuthorizedCode)

	if !hasClientCredentials && !hasPreAuthorizedCode {
		msg := fmt.Sprintf(
			"Auth Secret %q must contain either (%s and %s) or (%s) keys",
			secretKey.Name, AuthSecretKeyClientID, AuthSecretKeyClientSecret, AuthSecretKeyPreAuthorizedCode,
		)
		log.Info("Auth secret is missing required keys", "secret", secretKey)
		r.EventRecorder.Eventf(issuer, nil, corev1.EventTypeWarning, vcv1alpha1.ReasonAuthSecretInvalid, ActionValidateAuthSecret, msg)
		if statusErr := r.setErrorStatus(ctx, issuer, vcv1alpha1.ReasonAuthSecretInvalid, msg); statusErr != nil {
			return statusErr
		}
		return fmt.Errorf("auth secret invalid: %s", msg)
	}

	log.V(1).Info("Auth secret validated successfully", "secret", secretKey,
		"hasClientCredentials", hasClientCredentials, "hasPreAuthorizedCode", hasPreAuthorizedCode)
	return nil
}

// handleMetadataError handles a metadata discovery failure by updating the
// CredentialIssuer status conditions, recording a warning event, and returning
// the original error so controller-runtime applies exponential backoff.
func (r *CredentialIssuerReconciler) handleMetadataError(
	ctx context.Context,
	issuer *vcv1alpha1.CredentialIssuer,
	discoverErr error,
) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	msg := fmt.Sprintf("Failed to discover OID4VCI metadata from %s: %v", issuer.Spec.IssuerURL, discoverErr)
	log.Error(discoverErr, "Metadata discovery failed", "issuerURL", issuer.Spec.IssuerURL)
	r.EventRecorder.Eventf(issuer, nil, corev1.EventTypeWarning, vcv1alpha1.ReasonMetadataFetchFailed, ActionDiscoverMetadata, msg)

	if statusErr := r.setErrorStatus(ctx, issuer, vcv1alpha1.ReasonMetadataFetchFailed, msg); statusErr != nil {
		return ctrl.Result{}, statusErr
	}

	// Return the discovery error so controller-runtime applies exponential backoff
	// for transient network failures.
	return ctrl.Result{}, discoverErr
}

// handleMetadataSuccess updates the CredentialIssuer status with discovered
// metadata, sets the Ready condition to True, records a success event, and
// schedules the next metadata refresh after MetadataRefreshInterval.
func (r *CredentialIssuerReconciler) handleMetadataSuccess(
	ctx context.Context,
	issuer *vcv1alpha1.CredentialIssuer,
	metadata *oid4vci.IssuerMetadata,
) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Determine the token endpoint: use spec override if provided, otherwise
	// use the endpoint discovered from issuer metadata.
	tokenEndpoint := metadata.TokenEndpoint
	if issuer.Spec.TokenURL != "" {
		tokenEndpoint = issuer.Spec.TokenURL
		log.V(1).Info("Using token URL override from spec", "tokenURL", tokenEndpoint)
	}

	// Extract and sort supported credential type IDs for deterministic output.
	supportedTypes := extractSupportedTypes(metadata)

	// Update status fields with discovered metadata.
	now := metav1.Now()
	issuer.Status.IssuerIdentifier = metadata.CredentialIssuer
	issuer.Status.CredentialEndpoint = metadata.CredentialEndpoint
	issuer.Status.NonceEndpoint = metadata.NonceEndpoint
	issuer.Status.TokenEndpoint = tokenEndpoint
	issuer.Status.SupportedCredentialTypes = supportedTypes
	issuer.Status.LastMetadataFetchTime = &now

	// Set Ready=True condition.
	meta.SetStatusCondition(&issuer.Status.Conditions, metav1.Condition{
		Type:               vcv1alpha1.ConditionTypeReady,
		Status:             metav1.ConditionTrue,
		Reason:             vcv1alpha1.ReasonMetadataDiscovered,
		Message:            fmt.Sprintf("Successfully discovered OID4VCI metadata from %s", issuer.Spec.IssuerURL),
		ObservedGeneration: issuer.Generation,
	})

	// Clear any previous Error condition since the issuer is now healthy.
	meta.RemoveStatusCondition(&issuer.Status.Conditions, vcv1alpha1.ConditionTypeError)

	if err := r.Status().Update(ctx, issuer); err != nil {
		log.Error(err, "Failed to update CredentialIssuer status")
		return ctrl.Result{}, err
	}

	r.EventRecorder.Eventf(issuer, nil, corev1.EventTypeNormal, vcv1alpha1.ReasonMetadataDiscovered, ActionDiscoverMetadata,
		"Discovered OID4VCI metadata: credential_endpoint=%s, token_endpoint=%s, %d credential type(s) supported",
		metadata.CredentialEndpoint, tokenEndpoint, len(supportedTypes))

	log.Info("Successfully reconciled CredentialIssuer",
		"credentialEndpoint", metadata.CredentialEndpoint,
		"tokenEndpoint", tokenEndpoint,
		"supportedTypes", supportedTypes)

	return ctrl.Result{RequeueAfter: MetadataRefreshInterval}, nil
}

// setErrorStatus updates the CredentialIssuer status with Ready=False and
// Error=True conditions using the given reason and message. Both conditions
// are set simultaneously to indicate both that the issuer is not ready and
// that an error requires attention.
func (r *CredentialIssuerReconciler) setErrorStatus(
	ctx context.Context,
	issuer *vcv1alpha1.CredentialIssuer,
	reason, message string,
) error {
	log := logf.FromContext(ctx)

	meta.SetStatusCondition(&issuer.Status.Conditions, metav1.Condition{
		Type:               vcv1alpha1.ConditionTypeReady,
		Status:             metav1.ConditionFalse,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: issuer.Generation,
	})
	meta.SetStatusCondition(&issuer.Status.Conditions, metav1.Condition{
		Type:               vcv1alpha1.ConditionTypeError,
		Status:             metav1.ConditionTrue,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: issuer.Generation,
	})

	if err := r.Status().Update(ctx, issuer); err != nil {
		log.Error(err, "Failed to update CredentialIssuer status")
		return err
	}
	return nil
}

// extractSupportedTypes extracts credential type identifiers from the issuer
// metadata's credential_configurations_supported map and returns them sorted
// alphabetically for deterministic output.
func extractSupportedTypes(metadata *oid4vci.IssuerMetadata) []string {
	supportedTypes := make([]string, 0, len(metadata.CredentialConfigurationsSupported))
	for typeID := range metadata.CredentialConfigurationsSupported {
		supportedTypes = append(supportedTypes, typeID)
	}
	sort.Strings(supportedTypes)
	return supportedTypes
}

// hasSecretKey checks whether the given data map contains a non-empty value
// for the specified key.
func hasSecretKey(data map[string][]byte, key string) bool {
	val, ok := data[key]
	return ok && len(val) > 0
}

// SetupWithManager sets up the CredentialIssuer controller with the Manager.
// It watches CredentialIssuer resources and triggers reconciliation on changes.
func (r *CredentialIssuerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&vcv1alpha1.CredentialIssuer{}).
		Named("credentialissuer").
		Complete(r)
}
