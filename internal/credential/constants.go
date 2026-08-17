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

// Package credential provides utilities for parsing Verifiable Credentials
// in JWT format, extracting expiry information, and computing renewal schedules
// to support credential lifecycle management.
package credential

import "time"

// JWT segment and structure constants.
const (
	// JWTSegmentCount is the expected number of dot-separated segments
	// in a compact-serialized JWT (header.payload.signature).
	JWTSegmentCount = 3

	// JWTHeaderSegment is the index of the header segment in a compact JWT.
	JWTHeaderSegment = 0

	// JWTPayloadSegment is the index of the payload segment in a compact JWT.
	JWTPayloadSegment = 1

	// JWTSignatureSegment is the index of the signature segment in a compact JWT.
	JWTSignatureSegment = 2
)

// JWT claim names relevant to credential lifecycle management.
// The operator only extracts expiry-related claims; it does not interpret
// identity claims (iss, sub, jti) or VC-specific payload.
const (
	// ClaimExp is the JWT "exp" (Expiration Time) claim name.
	ClaimExp = "exp"

	// ClaimIat is the JWT "iat" (Issued At) claim name.
	ClaimIat = "iat"

	// ClaimVC is the JWT claim holding the Verifiable Credential object of a
	// jwt_vc_json credential.
	ClaimVC = "vc"
)

// Credential lifecycle constants.
const (
	// DefaultRenewBeforeDuration is the default duration before credential
	// expiry at which the operator triggers renewal. Used when no explicit
	// renewBefore is specified on the VerifiableCredentialRequest.
	DefaultRenewBeforeDuration = 5 * time.Minute

	// DefaultCredentialTTL is the default time-to-live applied to credentials
	// that do not have an explicit expiry claim. This ensures credentials
	// are periodically refreshed even when the issuer does not set an expiry.
	DefaultCredentialTTL = 24 * time.Hour

	// MaxCredentialLifetime is the maximum allowed credential lifetime.
	// Credentials with expiry times exceeding this limit from the issued-at
	// time are capped to this duration to prevent excessively long-lived credentials.
	MaxCredentialLifetime = 365 * 24 * time.Hour

	// MinRenewalInterval is the minimum interval between renewal attempts
	// to prevent tight renewal loops when credentials have very short lifetimes.
	MinRenewalInterval = 30 * time.Second
)
