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
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	vcv1alpha1 "github.com/SEAMWARE/vc-operator/api/v1alpha1"
	"github.com/SEAMWARE/vc-operator/internal/credential"
	"github.com/SEAMWARE/vc-operator/internal/credentialstore"
	"github.com/SEAMWARE/vc-operator/internal/oid4vci"
)

const (
	// IssuerNotReadyRequeueInterval is the interval to wait before retrying
	// reconciliation when the referenced CredentialIssuer is not yet Ready.
	IssuerNotReadyRequeueInterval = 30 * time.Second

	// TransientErrorBaseRequeueInterval is the base interval for exponential
	// backoff when transient OID4VCI errors occur.
	TransientErrorBaseRequeueInterval = 10 * time.Second

	// DefaultConfigErrorRequeueInterval is the default interval to wait before
	// retrying reconciliation after a non-transient configuration error. Can be
	// overridden per-reconciler via the ConfigErrorRequeueInterval field.
	DefaultConfigErrorRequeueInterval = 1 * time.Minute

	// ActionResolveIssuer is the event action recorded when the controller
	// resolves the referenced CredentialIssuer for a VerifiableCredentialRequest.
	ActionResolveIssuer = "ResolveIssuer"

	// ActionObtainToken is the event action recorded when the controller
	// obtains an OAuth 2.0 access token from the token endpoint.
	ActionObtainToken = "ObtainToken"

	// ActionRequestCredential is the event action recorded when the controller
	// requests a credential from the OID4VCI credential endpoint.
	ActionRequestCredential = "RequestCredential"

	// ActionStoreCredential is the event action recorded when the controller
	// stores a credential via the CredentialStore backend.
	ActionStoreCredential = "StoreCredential"

	// ActionCreateCredentialOffer is the event action recorded when the controller
	// creates a credential offer via the OID4VCI credential offer endpoint.
	ActionCreateCredentialOffer = "CreateCredentialOffer"

	// ActionResolveHolderKey is the event action recorded when the controller
	// resolves the holder key Secret for proof-of-possession generation.
	ActionResolveHolderKey = "ResolveHolderKey"

	// ActionRestoreCredential is the event action recorded when the controller
	// re-issues a credential because the stored one disappeared.
	ActionRestoreCredential = "RestoreCredential"

	// HolderKeySecretKeyPEM is the preferred data key in the holder key Secret
	// for the PEM-encoded ECDSA private key.
	HolderKeySecretKeyPEM = "key.pem"

	// HolderKeySecretKeyTLS is the fallback data key in the holder key Secret,
	// following the Kubernetes TLS Secret convention.
	HolderKeySecretKeyTLS = "tls.key"
)

// VerifiableCredentialRequestReconciler reconciles VerifiableCredentialRequest
// resources. It obtains Verifiable Credentials from OID4VCI issuers, stores
// them via the pluggable CredentialStore interface, and schedules automatic
// renewal before credential expiry.
type VerifiableCredentialRequestReconciler struct {
	client.Client
	Scheme          *runtime.Scheme
	OID4VCIClient   oid4vci.Client
	CredentialStore credentialstore.CredentialStore
	EventRecorder   events.EventRecorder

	// Clock provides an abstraction over time.Now() for testability.
	// If nil, RealClock is used. In tests, set to a FakeClock to
	// control time progression for renewal simulation.
	Clock Clock

	// Metrics holds Prometheus metric collectors for tracking credential
	// issuance, renewal, errors, and expiry. If nil, metrics are not recorded.
	Metrics *VCRequestMetrics

	// ConfigErrorRequeueInterval overrides the default interval between retries
	// after a non-transient configuration error. When zero,
	// DefaultConfigErrorRequeueInterval is used.
	ConfigErrorRequeueInterval time.Duration
}

// configErrorRequeueInterval returns the configured config error requeue
// interval, falling back to DefaultConfigErrorRequeueInterval when not set.
func (r *VerifiableCredentialRequestReconciler) configErrorRequeueInterval() time.Duration {
	if r.ConfigErrorRequeueInterval > 0 {
		return r.ConfigErrorRequeueInterval
	}
	return DefaultConfigErrorRequeueInterval
}

// now returns the current time from the injected Clock, falling back to
// RealClock if no Clock is configured.
func (r *VerifiableCredentialRequestReconciler) now() time.Time {
	if r.Clock != nil {
		return r.Clock.Now()
	}
	return time.Now()
}

// storedCredentialMissing reports whether the credential for this request is
// absent from the CredentialStore, either because the target Secret was
// deleted out-of-band or because it exists but carries no credential payload.
//
// A transient backend failure is deliberately reported as "present": a
// successful reconciliation resets the workqueue rate limiter, so treating
// every backend hiccup as a missing credential would let a flaky backend drive
// an unthrottled re-issuance storm against the issuer. The next renewal
// requeue, or the next Secret event, re-checks.
func (r *VerifiableCredentialRequestReconciler) storedCredentialMissing(
	ctx context.Context,
	vcReq *vcv1alpha1.VerifiableCredentialRequest,
) bool {
	data, err := r.CredentialStore.Retrieve(ctx, r.targetRefFor(vcReq))
	if errors.Is(err, credentialstore.ErrNotFound) {
		return true
	}
	if err != nil {
		logf.FromContext(ctx).Error(err, "Failed to check stored credential; assuming it is present",
			"targetSecret", vcReq.Spec.TargetSecretRef.Name)
		return false
	}
	return data == nil || len(data.Credential) == 0
}

// skipIfNotDueForRenewal checks whether the credential is already obtained,
// still stored, valid, and not yet due for renewal. Returns (result, true) to
// skip the full reconciliation when no work is needed, or (_, false) to
// proceed. A credentialMissing of true forces a full reconciliation regardless
// of the renewal schedule, so that a credential lost out-of-band is re-issued
// immediately instead of waiting for the scheduled renewal.
func (r *VerifiableCredentialRequestReconciler) skipIfNotDueForRenewal(
	vcReq *vcv1alpha1.VerifiableCredentialRequest,
	credentialMissing bool,
) (ctrl.Result, bool) {
	if credentialMissing {
		return ctrl.Result{}, false
	}

	readyCondition := meta.FindStatusCondition(vcReq.Status.Conditions, vcv1alpha1.ConditionTypeReady)
	if readyCondition == nil || readyCondition.Status != metav1.ConditionTrue {
		return ctrl.Result{}, false
	}

	if readyCondition.ObservedGeneration != vcReq.Generation {
		return ctrl.Result{}, false
	}

	if vcReq.Status.NextRenewalTime == nil {
		return ctrl.Result{}, false
	}

	now := r.now()
	timeUntilRenewal := vcReq.Status.NextRenewalTime.Sub(now)
	if timeUntilRenewal <= 0 {
		return ctrl.Result{}, false
	}

	return ctrl.Result{RequeueAfter: timeUntilRenewal}, true
}

// +kubebuilder:rbac:groups=vc.vc-operator.io,resources=verifiablecredentialrequests,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=vc.vc-operator.io,resources=verifiablecredentialrequests/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=vc.vc-operator.io,resources=verifiablecredentialrequests/finalizers,verbs=update
// +kubebuilder:rbac:groups=vc.vc-operator.io,resources=credentialissuers,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch

// Reconcile performs a single reconciliation cycle for a VerifiableCredentialRequest.
// It obtains a credential from the referenced CredentialIssuer via OID4VCI,
// stores it using the injected CredentialStore, and schedules renewal before expiry.
//
// The reconciliation flow:
//  1. Fetch the VerifiableCredentialRequest CR (return if deleted).
//  2. Look up the referenced CredentialIssuer and verify it is Ready.
//  3. Read authentication credentials from the issuer's auth Secret.
//  4. Obtain an OAuth 2.0 access token from the token endpoint.
//  5. Request the specified credential from the credential endpoint.
//  6. Parse the credential to extract expiry information.
//  7. Store the credential via the CredentialStore backend.
//  8. Update status with issuance/renewal timestamps and conditions.
//  9. Requeue after the computed renewal interval.
func (r *VerifiableCredentialRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	log.V(1).Info("Reconciling VerifiableCredentialRequest", "name", req.NamespacedName)

	// Step 1: Fetch the VerifiableCredentialRequest resource.
	var vcReq vcv1alpha1.VerifiableCredentialRequest
	if err := r.Get(ctx, req.NamespacedName, &vcReq); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("VerifiableCredentialRequest not found; ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to fetch VerifiableCredentialRequest")
		return ctrl.Result{}, err
	}

	// Step 1b: Check whether the stored credential is still present. The target
	// Secret may have been deleted or emptied out-of-band, in which case the
	// credential must be re-issued even though it is not yet due for renewal.
	credentialMissing := r.storedCredentialMissing(ctx, &vcReq)

	// Step 1c: Skip reconciliation if the credential is stored, still valid,
	// and not yet due for renewal. Status updates from handleSuccess trigger the
	// informer, which re-invokes Reconcile; without this guard, every
	// successful issuance immediately causes another full credential request.
	if result, skip := r.skipIfNotDueForRenewal(&vcReq, credentialMissing); skip {
		return result, nil
	}

	// A credential missing after a previous successful issuance is an
	// out-of-band deletion; surface it before spending an issuer round-trip.
	if credentialMissing && vcReq.Status.LastIssuanceTime != nil {
		r.recordCredentialMissing(ctx, &vcReq)
	}

	// Step 2: Look up the referenced CredentialIssuer and verify it is Ready.
	issuer, err := r.getReadyIssuer(ctx, &vcReq)
	if err != nil {
		return r.handleIssuerError(ctx, &vcReq, err)
	}

	// Step 3: Read authentication credentials from the issuer's auth Secret.
	tokenAuth, err := r.buildTokenAuth(ctx, issuer)
	if err != nil {
		return r.handleAuthError(ctx, &vcReq, err)
	}

	// Step 4: Obtain a credential-scoped access token.
	// For client_credentials auth, Keycloak's OID4VCI credential endpoint requires
	// authorization_details in the access token (RFC 9396), which the client_credentials
	// grant does not produce. Work around this by creating a pre-authorized credential
	// offer and exchanging the resulting code for a properly scoped token.
	var tokenResp *oid4vci.TokenResponse
	if tokenAuth.GrantType == oid4vci.GrantTypeClientCredentials {
		resp, err := r.obtainTokenViaCredentialOffer(ctx, issuer, tokenAuth, vcReq.Spec.CredentialType)
		if err != nil {
			return r.handleCredentialOfferError(ctx, &vcReq, err)
		}
		tokenResp = resp
	} else {
		resp, err := r.OID4VCIClient.ObtainAccessToken(ctx, issuer.Status.TokenEndpoint, *tokenAuth)
		if err != nil {
			return r.handleTokenError(ctx, &vcReq, err)
		}
		tokenResp = resp
	}

	// Step 5: Resolve holder key for proof-of-possession (if configured).
	holderKey, err := r.resolveHolderKey(ctx, &vcReq)
	if err != nil {
		return r.handleHolderKeyError(ctx, &vcReq, err)
	}

	// Step 6: Request the specified credential from the credential endpoint.
	// When the token response contains authorization_details with credential_identifiers,
	// the OID4VCI spec requires using credential_identifier instead of
	// credential_configuration_id + format.
	credReq, err := r.buildCredentialRequest(ctx, tokenResp, issuer, &vcReq, holderKey)
	if err != nil {
		return r.handleHolderKeyError(ctx, &vcReq, err)
	}
	credResp, err := r.OID4VCIClient.RequestCredential(
		ctx, issuer.Status.CredentialEndpoint, tokenResp.AccessToken, credReq,
	)
	if err != nil {
		return r.handleCredentialRequestError(ctx, &vcReq, err)
	}

	// Extract the credential as a string (JWT-based formats).
	credStr := credResp.CredentialAsString()
	if credStr == "" {
		msg := "credential response did not contain a string credential"
		return r.handlePermanentError(ctx, &vcReq, vcv1alpha1.ReasonCredentialRequestFailed, msg)
	}

	// Step 6: Parse the credential to extract expiry information.
	parsed, err := credential.ParseJWTCredential(credStr)
	if err != nil {
		msg := fmt.Sprintf("Failed to parse credential JWT: %v", err)
		return r.handlePermanentError(ctx, &vcReq, vcv1alpha1.ReasonCredentialRequestFailed, msg)
	}

	// Step 7: Compute renewal scheduling information.
	now := r.now()
	renewBefore := r.resolveRenewBefore(vcReq.Spec.RenewBefore)
	renewalInfo := credential.ComputeRenewalInfo(parsed, renewBefore, now)

	// Step 8: Store the credential via the CredentialStore backend.
	if err := r.storeCredential(ctx, &vcReq, credStr, credResp.Format, parsed); err != nil {
		return r.handleStorageError(ctx, &vcReq, err)
	}

	// Step 9: Update status with issuance/renewal timestamps and conditions.
	return r.handleSuccess(ctx, &vcReq, parsed, credResp.Format, renewalInfo, now)
}

// getReadyIssuer fetches the referenced CredentialIssuer and verifies that it
// has a Ready=True condition. Returns the issuer or an error describing why
// the issuer is not available.
func (r *VerifiableCredentialRequestReconciler) getReadyIssuer(
	ctx context.Context,
	vcReq *vcv1alpha1.VerifiableCredentialRequest,
) (*vcv1alpha1.CredentialIssuer, error) {
	log := logf.FromContext(ctx)

	var issuer vcv1alpha1.CredentialIssuer
	issuerKey := types.NamespacedName{
		Name:      vcReq.Spec.IssuerRef.Name,
		Namespace: vcReq.Namespace,
	}

	if err := r.Get(ctx, issuerKey, &issuer); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, &issuerError{
				reason:  vcv1alpha1.ReasonIssuerNotFound,
				message: fmt.Sprintf("CredentialIssuer %q not found in namespace %q", issuerKey.Name, issuerKey.Namespace),
			}
		}
		log.Error(err, "Failed to fetch CredentialIssuer", "issuer", issuerKey)
		return nil, err
	}

	readyCondition := meta.FindStatusCondition(issuer.Status.Conditions, vcv1alpha1.ConditionTypeReady)
	if readyCondition == nil || readyCondition.Status != metav1.ConditionTrue {
		return nil, &issuerError{
			reason:  vcv1alpha1.ReasonIssuerNotReady,
			message: fmt.Sprintf("CredentialIssuer %q is not Ready", issuerKey.Name),
		}
	}

	return &issuer, nil
}

// issuerError represents an error related to the referenced CredentialIssuer,
// carrying a machine-readable reason for status condition updates.
type issuerError struct {
	reason  string
	message string
}

// Error implements the error interface for issuerError.
func (e *issuerError) Error() string {
	return e.message
}

// buildTokenAuth reads the authentication Secret referenced by the given
// CredentialIssuer and constructs the TokenAuth parameters for the token
// request. It determines the appropriate grant type based on the available
// Secret keys.
func (r *VerifiableCredentialRequestReconciler) buildTokenAuth(
	ctx context.Context,
	issuer *vcv1alpha1.CredentialIssuer,
) (*oid4vci.TokenAuth, error) {
	log := logf.FromContext(ctx)

	secretKey := types.NamespacedName{
		Name:      issuer.Spec.AuthSecretRef.Name,
		Namespace: issuer.Namespace,
	}

	var secret corev1.Secret
	if err := r.Get(ctx, secretKey, &secret); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("auth Secret %q not found in namespace %q", secretKey.Name, secretKey.Namespace)
		}
		log.Error(err, "Failed to fetch auth Secret", "secret", secretKey)
		return nil, err
	}

	// Determine grant type from available Secret keys.
	if hasSecretKey(secret.Data, AuthSecretKeyClientID) && hasSecretKey(secret.Data, AuthSecretKeyClientSecret) {
		return &oid4vci.TokenAuth{
			GrantType:    oid4vci.GrantTypeClientCredentials,
			ClientID:     string(secret.Data[AuthSecretKeyClientID]),
			ClientSecret: string(secret.Data[AuthSecretKeyClientSecret]),
		}, nil
	}

	if hasSecretKey(secret.Data, AuthSecretKeyPreAuthorizedCode) {
		return &oid4vci.TokenAuth{
			GrantType:         oid4vci.GrantTypePreAuthorizedCode,
			PreAuthorizedCode: string(secret.Data[AuthSecretKeyPreAuthorizedCode]),
		}, nil
	}

	return nil, fmt.Errorf("auth Secret %q is missing required authentication keys", secretKey.Name)
}

// resolveFormat returns the credential format to use, defaulting to
// DefaultCredentialFormat if the spec does not specify one.
func (r *VerifiableCredentialRequestReconciler) resolveFormat(specFormat string) string {
	if specFormat == "" {
		return vcv1alpha1.DefaultCredentialFormat
	}
	return specFormat
}

// resolveRenewBefore returns the renew-before duration from the spec, or the
// default duration if not specified.
func (r *VerifiableCredentialRequestReconciler) resolveRenewBefore(renewBefore *metav1.Duration) time.Duration {
	if renewBefore != nil {
		return renewBefore.Duration
	}
	return credential.DefaultRenewBeforeDuration
}

// targetRefFor builds the CredentialStore reference for the request's target
// Secret, including the owner information used for garbage collection.
func (r *VerifiableCredentialRequestReconciler) targetRefFor(
	vcReq *vcv1alpha1.VerifiableCredentialRequest,
) credentialstore.TargetRef {
	return credentialstore.TargetRef{
		Namespace: vcReq.Namespace,
		Name:      vcReq.Spec.TargetSecretRef.Name,
		Key:       vcReq.Spec.TargetSecretRef.Key,
		OwnerGVK: metav1.GroupVersionKind{
			Group:   vcv1alpha1.GroupVersion.Group,
			Version: vcv1alpha1.GroupVersion.Version,
			Kind:    "VerifiableCredentialRequest",
		},
		OwnerUID:  vcReq.UID,
		OwnerName: vcReq.Name,
	}
}

// storeCredential persists the obtained credential via the CredentialStore
// backend, setting up proper owner references for garbage collection.
func (r *VerifiableCredentialRequestReconciler) storeCredential(
	ctx context.Context,
	vcReq *vcv1alpha1.VerifiableCredentialRequest,
	credStr string,
	format string,
	parsed *credential.ParsedCredential,
) error {
	targetRef := r.targetRefFor(vcReq)

	// Try to retrieve existing credential for rotation buffer.
	var previousCredential []byte
	existing, err := r.CredentialStore.Retrieve(ctx, targetRef)
	if err == nil && existing != nil && len(existing.Credential) > 0 {
		previousCredential = existing.Credential
	}

	credData := &credentialstore.CredentialData{
		Credential:         []byte(credStr),
		Format:             format,
		ExpiryTime:         parsed.Expiry,
		IssuedAt:           parsed.IssuedAt,
		PreviousCredential: previousCredential,
	}

	return r.CredentialStore.Store(ctx, targetRef, credData)
}

// handleIssuerError handles errors related to the referenced CredentialIssuer
// (not found or not Ready). It sets the appropriate status conditions and
// requeues after IssuerNotReadyRequeueInterval.
func (r *VerifiableCredentialRequestReconciler) handleIssuerError(
	ctx context.Context,
	vcReq *vcv1alpha1.VerifiableCredentialRequest,
	err error,
) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	if ie, ok := err.(*issuerError); ok {
		log.Info("Issuer not available", "reason", ie.reason, "message", ie.message)
		r.EventRecorder.Eventf(vcReq, nil, corev1.EventTypeWarning, ie.reason, ActionResolveIssuer, ie.message)
		r.recordErrorMetric(vcReq, ie.reason)

		if statusErr := r.setVCRequestErrorStatus(ctx, vcReq, ie.reason, ie.message); statusErr != nil {
			return ctrl.Result{}, statusErr
		}
		return ctrl.Result{RequeueAfter: IssuerNotReadyRequeueInterval}, nil
	}

	// Unexpected error (e.g., API server failure) — return for exponential backoff.
	log.Error(err, "Unexpected error looking up CredentialIssuer")
	return ctrl.Result{}, err
}

// handleAuthError handles errors reading the authentication Secret. These are
// configuration errors that require user intervention, so we set an error
// condition and requeue after a fixed interval.
func (r *VerifiableCredentialRequestReconciler) handleAuthError(
	ctx context.Context,
	vcReq *vcv1alpha1.VerifiableCredentialRequest,
	err error,
) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	msg := fmt.Sprintf("Failed to read auth credentials: %v", err)
	log.Info("Auth credential error", "error", err)
	r.EventRecorder.Eventf(vcReq, nil, corev1.EventTypeWarning, vcv1alpha1.ReasonAuthSecretNotFound, ActionObtainToken, msg)
	r.recordErrorMetric(vcReq, vcv1alpha1.ReasonAuthSecretNotFound)

	if statusErr := r.setVCRequestErrorStatus(ctx, vcReq, vcv1alpha1.ReasonAuthSecretNotFound, msg); statusErr != nil {
		return ctrl.Result{}, statusErr
	}
	return ctrl.Result{RequeueAfter: r.configErrorRequeueInterval()}, nil
}

// handleTokenError handles failures from the token endpoint. Token errors are
// typically transient (network issues, temporary auth problems), so we return
// the error to trigger exponential backoff via controller-runtime.
func (r *VerifiableCredentialRequestReconciler) handleTokenError(
	ctx context.Context,
	vcReq *vcv1alpha1.VerifiableCredentialRequest,
	err error,
) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	msg := fmt.Sprintf("Failed to obtain access token: %v", err)
	log.Error(err, "Token request failed")
	r.EventRecorder.Eventf(vcReq, nil, corev1.EventTypeWarning, vcv1alpha1.ReasonTokenRequestFailed, ActionObtainToken, msg)
	r.recordErrorMetric(vcReq, vcv1alpha1.ReasonTokenRequestFailed)

	if statusErr := r.setVCRequestErrorStatus(ctx, vcReq, vcv1alpha1.ReasonTokenRequestFailed, msg); statusErr != nil {
		return ctrl.Result{}, statusErr
	}
	// Return the original error so controller-runtime applies exponential backoff.
	return ctrl.Result{}, err
}

// handleCredentialRequestError handles failures from the credential endpoint.
// Returns the error for exponential backoff.
func (r *VerifiableCredentialRequestReconciler) handleCredentialRequestError(
	ctx context.Context,
	vcReq *vcv1alpha1.VerifiableCredentialRequest,
	err error,
) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	msg := fmt.Sprintf("Failed to request credential: %v", err)
	log.Error(err, "Credential request failed")
	r.EventRecorder.Eventf(vcReq, nil, corev1.EventTypeWarning, vcv1alpha1.ReasonCredentialRequestFailed, ActionRequestCredential, msg)
	r.recordErrorMetric(vcReq, vcv1alpha1.ReasonCredentialRequestFailed)

	if statusErr := r.setVCRequestErrorStatus(ctx, vcReq, vcv1alpha1.ReasonCredentialRequestFailed, msg); statusErr != nil {
		return ctrl.Result{}, statusErr
	}
	return ctrl.Result{}, err
}

// handlePermanentError handles non-retriable errors (e.g., invalid credential
// format, unparseable JWT). Sets an error condition and requeues after a fixed
// interval since the error requires user intervention or issuer-side fix.
func (r *VerifiableCredentialRequestReconciler) handlePermanentError(
	ctx context.Context,
	vcReq *vcv1alpha1.VerifiableCredentialRequest,
	reason, message string,
) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	log.Info("Permanent error during credential acquisition", "reason", reason, "message", message)
	r.EventRecorder.Eventf(vcReq, nil, corev1.EventTypeWarning, reason, ActionRequestCredential, message)
	r.recordErrorMetric(vcReq, reason)

	if statusErr := r.setVCRequestErrorStatus(ctx, vcReq, reason, message); statusErr != nil {
		return ctrl.Result{}, statusErr
	}
	return ctrl.Result{RequeueAfter: r.configErrorRequeueInterval()}, nil
}

// handleStorageError handles failures from the CredentialStore backend.
// Returns the error for exponential backoff since storage failures are
// often transient (API server connectivity, etc.).
func (r *VerifiableCredentialRequestReconciler) handleStorageError(
	ctx context.Context,
	vcReq *vcv1alpha1.VerifiableCredentialRequest,
	err error,
) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	msg := fmt.Sprintf("Failed to store credential: %v", err)
	log.Error(err, "Credential storage failed")
	r.EventRecorder.Eventf(vcReq, nil, corev1.EventTypeWarning, vcv1alpha1.ReasonStorageFailed, ActionStoreCredential, msg)
	r.recordErrorMetric(vcReq, vcv1alpha1.ReasonStorageFailed)

	if statusErr := r.setVCRequestErrorStatus(ctx, vcReq, vcv1alpha1.ReasonStorageFailed, msg); statusErr != nil {
		return ctrl.Result{}, statusErr
	}
	return ctrl.Result{}, err
}

// handleSuccess updates the VerifiableCredentialRequest status after successful
// credential issuance. It sets the CredentialIssued, Ready, and RenewalScheduled
// conditions, records timestamps, and computes the requeue interval.
func (r *VerifiableCredentialRequestReconciler) handleSuccess(
	ctx context.Context,
	vcReq *vcv1alpha1.VerifiableCredentialRequest,
	parsed *credential.ParsedCredential,
	format string,
	renewalInfo *credential.RenewalInfo,
	now time.Time,
) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	metaNow := metav1.NewTime(now)

	// Determine if this is a renewal (previous issuance exists) or initial issuance.
	isRenewal := vcReq.Status.LastIssuanceTime != nil

	// Update status timestamps and renewal counter.
	vcReq.Status.LastIssuanceTime = &metaNow
	if isRenewal {
		vcReq.Status.LastRenewalTime = &metaNow
		vcReq.Status.RenewalCount++
	}
	vcReq.Status.CredentialFormat = format

	if parsed.HasExpiry() {
		expiryTime := metav1.NewTime(parsed.Expiry)
		vcReq.Status.CredentialExpiryTime = &expiryTime
	} else {
		vcReq.Status.CredentialExpiryTime = nil
	}

	renewalTime := metav1.NewTime(renewalInfo.RenewalTime)
	vcReq.Status.NextRenewalTime = &renewalTime

	// Set CredentialIssued=True condition.
	meta.SetStatusCondition(&vcReq.Status.Conditions, metav1.Condition{
		Type:               vcv1alpha1.ConditionTypeCredentialIssued,
		Status:             metav1.ConditionTrue,
		Reason:             vcv1alpha1.ReasonCredentialObtained,
		Message:            fmt.Sprintf("Credential of type %q successfully obtained and stored", vcReq.Spec.CredentialType),
		ObservedGeneration: vcReq.Generation,
	})

	// Set Ready=True condition.
	meta.SetStatusCondition(&vcReq.Status.Conditions, metav1.Condition{
		Type:               vcv1alpha1.ConditionTypeReady,
		Status:             metav1.ConditionTrue,
		Reason:             vcv1alpha1.ReasonCredentialObtained,
		Message:            "Credential is stored and valid",
		ObservedGeneration: vcReq.Generation,
	})

	// Set RenewalScheduled=True condition.
	meta.SetStatusCondition(&vcReq.Status.Conditions, metav1.Condition{
		Type:               vcv1alpha1.ConditionTypeRenewalScheduled,
		Status:             metav1.ConditionTrue,
		Reason:             vcv1alpha1.ReasonRenewalScheduled,
		Message:            fmt.Sprintf("Next renewal scheduled at %s", renewalInfo.RenewalTime.Format(time.RFC3339)),
		ObservedGeneration: vcReq.Generation,
	})

	// Clear any previous Error condition since issuance succeeded.
	meta.RemoveStatusCondition(&vcReq.Status.Conditions, vcv1alpha1.ConditionTypeError)

	if err := r.Status().Update(ctx, vcReq); err != nil {
		log.Error(err, "Failed to update VerifiableCredentialRequest status")
		return ctrl.Result{}, err
	}

	// Record success event and update metrics.
	eventMsg := fmt.Sprintf("Credential %q obtained and stored in %s/%s",
		vcReq.Spec.CredentialType, vcReq.Namespace, vcReq.Spec.TargetSecretRef.Name)
	if isRenewal {
		r.EventRecorder.Eventf(vcReq, nil, corev1.EventTypeNormal, vcv1alpha1.ReasonCredentialObtained, ActionRequestCredential,
			"Renewed: "+eventMsg)
	} else {
		r.EventRecorder.Eventf(vcReq, nil, corev1.EventTypeNormal, vcv1alpha1.ReasonCredentialObtained, ActionRequestCredential, eventMsg)
	}
	r.recordSuccessMetrics(vcReq, isRenewal, parsed)

	// Compute requeue interval from renewal info.
	requeueAfter := renewalInfo.TimeUntilRenewal
	if requeueAfter <= 0 {
		// Renewal is already overdue; use the minimum interval to avoid tight loops.
		requeueAfter = credential.MinRenewalInterval
	}

	log.Info("Successfully reconciled VerifiableCredentialRequest",
		"credentialType", vcReq.Spec.CredentialType,
		"format", format,
		"isRenewal", isRenewal,
		"requeueAfter", requeueAfter)

	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}

// setVCRequestErrorStatus updates the VerifiableCredentialRequest status with
// Ready=False and Error=True conditions using the given reason and message.
func (r *VerifiableCredentialRequestReconciler) setVCRequestErrorStatus(
	ctx context.Context,
	vcReq *vcv1alpha1.VerifiableCredentialRequest,
	reason, message string,
) error {
	log := logf.FromContext(ctx)

	meta.SetStatusCondition(&vcReq.Status.Conditions, metav1.Condition{
		Type:               vcv1alpha1.ConditionTypeReady,
		Status:             metav1.ConditionFalse,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: vcReq.Generation,
	})
	meta.SetStatusCondition(&vcReq.Status.Conditions, metav1.Condition{
		Type:               vcv1alpha1.ConditionTypeError,
		Status:             metav1.ConditionTrue,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: vcReq.Generation,
	})

	if err := r.Status().Update(ctx, vcReq); err != nil {
		log.Error(err, "Failed to update VerifiableCredentialRequest status")
		return err
	}
	return nil
}

// recordCredentialMissing logs and emits a Warning event reporting that a
// previously issued credential is no longer present in the storage backend.
// It is a Warning rather than a Normal event because an operator-managed
// resource was destroyed from outside the operator, and recovering from it
// costs a full round-trip to the issuer.
func (r *VerifiableCredentialRequestReconciler) recordCredentialMissing(
	ctx context.Context,
	vcReq *vcv1alpha1.VerifiableCredentialRequest,
) {
	logf.FromContext(ctx).Info("Stored credential missing; triggering re-issuance",
		"targetSecret", vcReq.Spec.TargetSecretRef.Name)

	msg := fmt.Sprintf("Stored credential %s/%s is missing; requesting a replacement from the issuer",
		vcReq.Namespace, vcReq.Spec.TargetSecretRef.Name)
	r.EventRecorder.Eventf(vcReq, nil, corev1.EventTypeWarning,
		vcv1alpha1.ReasonStoredCredentialMissing, ActionRestoreCredential, msg)
}

// recordErrorMetric increments the credentials_errors_total counter if metrics
// are configured. The reason label identifies the error category.
func (r *VerifiableCredentialRequestReconciler) recordErrorMetric(vcReq *vcv1alpha1.VerifiableCredentialRequest, reason string) {
	if r.Metrics != nil {
		r.Metrics.CredentialsErrorsTotal.WithLabelValues(
			vcReq.Namespace, vcReq.Name, reason,
		).Inc()
	}
}

// recordSuccessMetrics increments issuance/renewal counters and updates the
// credential expiry gauge if metrics are configured.
func (r *VerifiableCredentialRequestReconciler) recordSuccessMetrics(
	vcReq *vcv1alpha1.VerifiableCredentialRequest,
	isRenewal bool,
	parsed *credential.ParsedCredential,
) {
	if r.Metrics == nil {
		return
	}
	labels := []string{vcReq.Namespace, vcReq.Name, vcReq.Spec.CredentialType}
	if isRenewal {
		r.Metrics.CredentialsRenewedTotal.WithLabelValues(labels...).Inc()
	} else {
		r.Metrics.CredentialsIssuedTotal.WithLabelValues(labels...).Inc()
	}

	if parsed.HasExpiry() {
		r.Metrics.CredentialExpirySeconds.WithLabelValues(labels...).Set(
			float64(parsed.Expiry.Unix()),
		)
	}
}

// obtainTokenViaCredentialOffer implements the pre-authorized code flow:
//  1. Obtain an admin token via client_credentials grant.
//  2. Create a pre-authorized credential offer for the requested credential type.
//  3. Fetch the full offer to extract the pre-authorized code.
//  4. Exchange the pre-authorized code for a credential-scoped access token
//     that contains authorization_details required by the credential endpoint.
//
// Returns the full TokenResponse so the caller can extract credential_identifiers
// from the authorization_details for the credential request.
func (r *VerifiableCredentialRequestReconciler) obtainTokenViaCredentialOffer(
	ctx context.Context,
	issuer *vcv1alpha1.CredentialIssuer,
	tokenAuth *oid4vci.TokenAuth,
	credentialType string,
) (*oid4vci.TokenResponse, error) {
	log := logf.FromContext(ctx)

	// Step 1: Get admin token via client_credentials.
	adminToken, err := r.OID4VCIClient.ObtainAccessToken(ctx, issuer.Status.TokenEndpoint, *tokenAuth)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain admin token: %w", err)
	}

	// Step 2: Create a pre-authorized credential offer.
	log.V(1).Info("Creating credential offer", "credentialType", credentialType)
	offerURI, err := r.OID4VCIClient.CreateCredentialOffer(
		ctx, issuer.Spec.IssuerURL, adminToken.AccessToken, credentialType,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create credential offer: %w", err)
	}

	// Step 3: Fetch the full credential offer to get the pre-authorized code.
	offer, err := r.OID4VCIClient.FetchCredentialOffer(ctx, issuer.Spec.IssuerURL, offerURI.Nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch credential offer: %w", err)
	}

	preAuthCode, err := offer.PreAuthorizedCode()
	if err != nil {
		return nil, fmt.Errorf("credential offer missing pre-authorized code: %w", err)
	}

	// Step 4: Exchange pre-authorized code for a credential-scoped token.
	log.V(1).Info("Exchanging pre-authorized code for credential token")
	preAuthToken, err := r.OID4VCIClient.ObtainAccessToken(ctx, issuer.Status.TokenEndpoint, oid4vci.TokenAuth{
		GrantType:         oid4vci.GrantTypePreAuthorizedCode,
		PreAuthorizedCode: preAuthCode,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to exchange pre-authorized code for token: %w", err)
	}

	log.Info("Successfully obtained credential-scoped token via pre-authorized code flow",
		"credentialType", credentialType)

	return preAuthToken, nil
}

// buildCredentialRequest constructs the credential request based on the token response.
// When the token response contains authorization_details with credential_identifiers,
// the request uses credential_identifier per OID4VCI spec section 7.2.
// Otherwise, it falls back to credential_configuration_id + format.
// If a holder key is provided, a proof-of-possession JWT is generated and included.
// Keycloak issuers require the OID4VCI draft 14+ "proofs" (plural) format for key
// binding to take effect; generic issuers use the draft <=13 "proof" (singular) format.
func (r *VerifiableCredentialRequestReconciler) buildCredentialRequest(
	ctx context.Context,
	tokenResp *oid4vci.TokenResponse,
	issuer *vcv1alpha1.CredentialIssuer,
	vcReq *vcv1alpha1.VerifiableCredentialRequest,
	holderKey *ecdsa.PrivateKey,
) (oid4vci.CredentialRequest, error) {
	var credReq oid4vci.CredentialRequest

	credIdentifier := tokenResp.CredentialIdentifierForConfig(vcReq.Spec.CredentialType)
	if credIdentifier != "" {
		credReq.CredentialIdentifier = credIdentifier
	} else {
		credReq.CredentialConfigurationID = vcReq.Spec.CredentialType
		credReq.Format = r.resolveFormat(vcReq.Spec.Format)
	}

	if holderKey != nil {
		log := logf.FromContext(ctx)
		proofAudience := issuer.Status.IssuerIdentifier
		if proofAudience == "" {
			proofAudience = issuer.Spec.IssuerURL
		}
		cNonce := tokenResp.CNonce
		if cNonce == "" && issuer.Status.NonceEndpoint != "" {
			var nonceErr error
			cNonce, nonceErr = r.OID4VCIClient.FetchNonce(ctx, issuer.Status.NonceEndpoint, tokenResp.AccessToken)
			if nonceErr != nil {
				log.Error(nonceErr, "Failed to fetch nonce from nonce endpoint")
				return oid4vci.CredentialRequest{}, fmt.Errorf("failed to fetch nonce: %w", nonceErr)
			}
		}
		proofJWT, err := oid4vci.GenerateProofJWT(holderKey, proofAudience, cNonce, vcReq.Spec.HolderDID)
		if err != nil {
			log.Error(err, "Failed to generate proof-of-possession JWT")
			return oid4vci.CredentialRequest{}, fmt.Errorf("failed to generate proof JWT: %w", err)
		}
		if issuer.Spec.IssuerType == "keycloak" {
			credReq.Proofs = map[string][]string{
				oid4vci.ProofTypeJWT: {proofJWT},
			}
		} else {
			credReq.Proof = &oid4vci.CredentialProof{
				ProofType: oid4vci.ProofTypeJWT,
				JWT:       proofJWT,
			}
		}
	}

	return credReq, nil
}

// resolveHolderKey reads and parses the holder's ECDSA private key from the
// Secret referenced by spec.holderKeyRef. Returns nil if no holder key is
// configured. Returns an error if holderDID is set without holderKeyRef, or
// if the referenced Secret is missing/invalid.
func (r *VerifiableCredentialRequestReconciler) resolveHolderKey(
	ctx context.Context,
	vcReq *vcv1alpha1.VerifiableCredentialRequest,
) (*ecdsa.PrivateKey, error) {
	log := logf.FromContext(ctx)

	if vcReq.Spec.HolderDID != "" && vcReq.Spec.HolderKeyRef == nil {
		return nil, fmt.Errorf("holderDID requires holderKeyRef to be set")
	}

	if vcReq.Spec.HolderKeyRef == nil {
		return nil, nil
	}

	secretKey := types.NamespacedName{
		Name:      vcReq.Spec.HolderKeyRef.Name,
		Namespace: vcReq.Namespace,
	}

	var secret corev1.Secret
	if err := r.Get(ctx, secretKey, &secret); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("holder key Secret %q not found in namespace %q", secretKey.Name, secretKey.Namespace)
		}
		log.Error(err, "Failed to fetch holder key Secret", "secret", secretKey)
		return nil, err
	}

	var pemData []byte
	if data, ok := secret.Data[HolderKeySecretKeyPEM]; ok && len(data) > 0 {
		pemData = data
	} else if data, ok := secret.Data[HolderKeySecretKeyTLS]; ok && len(data) > 0 {
		pemData = data
	} else {
		return nil, fmt.Errorf("holder key Secret %q missing required key (%s or %s)", secretKey.Name, HolderKeySecretKeyPEM, HolderKeySecretKeyTLS)
	}

	km, err := oid4vci.NewKeyManagerFromPEM(pemData)
	if err != nil {
		return nil, fmt.Errorf("holder key Secret %q contains invalid key data: %w", secretKey.Name, err)
	}

	log.V(1).Info("Resolved holder key from Secret", "secret", secretKey.Name)
	return km.PrivateKey(), nil
}

// handleHolderKeyError handles errors related to the holder key Secret
// (not found, missing key data, or invalid configuration).
func (r *VerifiableCredentialRequestReconciler) handleHolderKeyError(
	ctx context.Context,
	vcReq *vcv1alpha1.VerifiableCredentialRequest,
	err error,
) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	msg := fmt.Sprintf("Holder key error: %v", err)
	log.Info("Holder key configuration error", "error", err)
	r.EventRecorder.Eventf(vcReq, nil, corev1.EventTypeWarning, vcv1alpha1.ReasonHolderKeyInvalid, ActionResolveHolderKey, msg)
	r.recordErrorMetric(vcReq, vcv1alpha1.ReasonHolderKeyInvalid)

	if statusErr := r.setVCRequestErrorStatus(ctx, vcReq, vcv1alpha1.ReasonHolderKeyInvalid, msg); statusErr != nil {
		return ctrl.Result{}, statusErr
	}
	return ctrl.Result{RequeueAfter: r.configErrorRequeueInterval()}, nil
}

// handleCredentialOfferError handles failures from the credential offer flow.
// Returns the error for exponential backoff.
func (r *VerifiableCredentialRequestReconciler) handleCredentialOfferError(
	ctx context.Context,
	vcReq *vcv1alpha1.VerifiableCredentialRequest,
	err error,
) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	msg := fmt.Sprintf("Failed to obtain credential token via pre-authorized code flow: %v", err)
	log.Error(err, "Credential offer flow failed")
	r.EventRecorder.Eventf(vcReq, nil, corev1.EventTypeWarning, vcv1alpha1.ReasonCredentialRequestFailed, ActionCreateCredentialOffer, msg)
	r.recordErrorMetric(vcReq, vcv1alpha1.ReasonCredentialRequestFailed)

	if statusErr := r.setVCRequestErrorStatus(ctx, vcReq, vcv1alpha1.ReasonCredentialRequestFailed, msg); statusErr != nil {
		return ctrl.Result{}, statusErr
	}
	return ctrl.Result{}, err
}

// SetupWithManager sets up the VerifiableCredentialRequest controller with the
// Manager. It watches VerifiableCredentialRequest resources and the credential
// Secrets they own, so that a Secret deleted or emptied out-of-band is
// re-created without waiting for the scheduled renewal.
func (r *VerifiableCredentialRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&vcv1alpha1.VerifiableCredentialRequest{}).
		Owns(&corev1.Secret{}, builder.WithPredicates(credentialSecretPredicate())).
		Named("verifiablecredentialrequest").
		Complete(r)
}

// credentialSecretPredicate filters events on owned credential Secrets down to
// the ones that can indicate credential loss. Creates and updates produced by
// the operator's own Store calls are ignored: the operator's own writes can
// never be the thing it needs to react to, and letting them through would
// enqueue a redundant reconciliation after every issuance as well as one per
// managed Secret on every informer resync. Only deletions, and updates that
// removed or emptied a data key, are relevant.
//
// The data-key check is deliberately a superset of "the credential key was
// emptied": the predicate has no access to spec.targetSecretRef.key. A false
// positive costs one cached read, after which the reconciliation skips.
func credentialSecretPredicate() predicate.Predicate {
	return predicate.Funcs{
		CreateFunc:  func(event.CreateEvent) bool { return false },
		GenericFunc: func(event.GenericEvent) bool { return false },
		DeleteFunc:  func(event.DeleteEvent) bool { return true },
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldSecret, okOld := e.ObjectOld.(*corev1.Secret)
			newSecret, okNew := e.ObjectNew.(*corev1.Secret)
			if !okOld || !okNew {
				return false
			}
			for key, value := range oldSecret.Data {
				if len(value) == 0 {
					continue
				}
				if len(newSecret.Data[key]) == 0 {
					return true
				}
			}
			return false
		},
	}
}
