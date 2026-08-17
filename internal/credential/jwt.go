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

package credential

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ParsedCredential holds the expiry-related information extracted from a
// parsed JWT Verifiable Credential. The operator only needs lifecycle data
// (expiry and issued-at times) to schedule credential renewal; it does not
// interpret identity claims or VC-specific payload.
type ParsedCredential struct {
	// RawJWT is the original compact-serialized JWT string.
	RawJWT string

	// IssuedAt is the time extracted from the "iat" (Issued At) claim.
	// Zero value if the claim is absent.
	IssuedAt time.Time

	// Expiry is the time extracted from the "exp" (Expiration Time) claim.
	// Zero value if the claim is absent, meaning the credential does not expire.
	Expiry time.Time
}

// HasExpiry reports whether the parsed credential contains an explicit
// expiry time (the "exp" claim was present and valid).
func (pc *ParsedCredential) HasExpiry() bool {
	return !pc.Expiry.IsZero()
}

// IsExpired reports whether the credential has expired relative to the
// given reference time. Returns false if no expiry is set.
func (pc *ParsedCredential) IsExpired(now time.Time) bool {
	if !pc.HasExpiry() {
		return false
	}
	return now.After(pc.Expiry)
}

// ParseJWTCredential parses a compact-serialized JWT Verifiable Credential
// and extracts the expiry-related claims needed for credential lifecycle
// management (exp and iat). It does NOT verify the JWT signature — the
// operator trusts the issuer; signature verification is the holder/verifier's
// responsibility.
//
// The JWT must have three dot-separated segments (header.payload.signature).
// Only the payload segment is decoded and parsed for expiry information.
func ParseJWTCredential(rawJWT string) (*ParsedCredential, error) {
	rawJWT = strings.TrimSpace(rawJWT)
	if rawJWT == "" {
		return nil, fmt.Errorf("empty JWT string")
	}

	segments := strings.Split(rawJWT, ".")
	if len(segments) != JWTSegmentCount {
		return nil, fmt.Errorf("invalid JWT: expected %d segments, got %d", JWTSegmentCount, len(segments))
	}

	// Decode and parse the payload segment to extract expiry information.
	payload, err := decodeJWTSegment(segments[JWTPayloadSegment])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	pc := &ParsedCredential{
		RawJWT:   rawJWT,
		Expiry:   extractTimeClaim(payload, ClaimExp),
		IssuedAt: extractTimeClaim(payload, ClaimIat),
	}

	return pc, nil
}

// decodeJWTSegment decodes a Base64url-encoded JWT segment and parses it
// as a JSON object. It handles both padded and unpadded Base64url encoding.
func decodeJWTSegment(segment string) (map[string]any, error) {
	// Base64url decode (JWT uses raw URL encoding without padding).
	decoded, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		// Try with standard padding as a fallback.
		decoded, err = base64.URLEncoding.DecodeString(addBase64Padding(segment))
		if err != nil {
			return nil, fmt.Errorf("base64 decode failed: %w", err)
		}
	}

	var claims map[string]any
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil, fmt.Errorf("JSON unmarshal failed: %w", err)
	}

	return claims, nil
}

// addBase64Padding adds standard Base64 padding characters to a Base64url
// string that may be missing padding.
func addBase64Padding(s string) string {
	switch len(s) % 4 {
	case 2:
		return s + "=="
	case 3:
		return s + "="
	default:
		return s
	}
}

// extractTimeClaim extracts a Unix timestamp from a JWT claims map and
// converts it to a time.Time. Handles both integer and floating-point
// representations of the timestamp. Returns zero time if the claim is
// absent or not a valid number.
func extractTimeClaim(claims map[string]any, key string) time.Time {
	val, ok := claims[key]
	if !ok {
		return time.Time{}
	}
	// JSON numbers are decoded as float64 by encoding/json.
	switch v := val.(type) {
	case float64:
		if v <= 0 {
			return time.Time{}
		}
		return time.Unix(int64(v), 0)
	case json.Number:
		n, err := v.Int64()
		if err != nil || n <= 0 {
			return time.Time{}
		}
		return time.Unix(n, 0)
	default:
		return time.Time{}
	}
}

// ExtractVCClaim returns the "vc" claim of a JWT Verifiable Credential as raw
// JSON, i.e. the credential object itself rather than the enclosing JWT.
//
// Consumers that store a credential alongside its compact form need both: the
// raw JWT carries the signature, while the decoded object is what a credential
// store indexes and evaluates. As with ParseJWTCredential, the signature is not
// verified here.
func ExtractVCClaim(rawJWT string) (json.RawMessage, error) {
	rawJWT = strings.TrimSpace(rawJWT)
	segments := strings.Split(rawJWT, ".")
	if len(segments) != JWTSegmentCount {
		return nil, fmt.Errorf("invalid JWT: expected %d segments, got %d", JWTSegmentCount, len(segments))
	}

	payload, err := decodeJWTSegment(segments[JWTPayloadSegment])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	vc, ok := payload[ClaimVC]
	if !ok {
		return nil, fmt.Errorf("JWT payload has no %q claim", ClaimVC)
	}

	encoded, err := json.Marshal(vc)
	if err != nil {
		return nil, fmt.Errorf("failed to re-encode the %q claim: %w", ClaimVC, err)
	}

	return encoded, nil
}
