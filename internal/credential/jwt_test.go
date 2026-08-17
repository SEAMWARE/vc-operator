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
	"testing"
	"time"
)

// buildJWT constructs a compact-serialized JWT from header and payload maps.
// The signature segment is a fixed placeholder since the parser does not verify signatures.
func buildJWT(header, payload map[string]any) string {
	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	return headerB64 + "." + payloadB64 + ".signature-placeholder"
}

func TestParseJWTCredential(t *testing.T) {
	now := time.Now()
	expTime := now.Add(1 * time.Hour)
	iatTime := now.Add(-5 * time.Minute)

	tests := []struct {
		name       string
		rawJWT     string
		wantExpiry bool
		wantIat    bool
		wantErr    bool
	}{
		{
			name: "JWT with both exp and iat claims",
			rawJWT: buildJWT(
				map[string]any{"alg": "ES256", "typ": "JWT"},
				map[string]any{
					ClaimExp: float64(expTime.Unix()),
					ClaimIat: float64(iatTime.Unix()),
					"iss":    "https://issuer.example.com",
					"sub":    "did:example:holder123",
				},
			),
			wantExpiry: true,
			wantIat:    true,
			wantErr:    false,
		},
		{
			name: "JWT with only expiry",
			rawJWT: buildJWT(
				map[string]any{"alg": "ES256"},
				map[string]any{
					ClaimExp: float64(expTime.Unix()),
				},
			),
			wantExpiry: true,
			wantIat:    false,
			wantErr:    false,
		},
		{
			name: "JWT without expiry claim",
			rawJWT: buildJWT(
				map[string]any{"alg": "ES256"},
				map[string]any{
					ClaimIat: float64(iatTime.Unix()),
				},
			),
			wantExpiry: false,
			wantIat:    true,
			wantErr:    false,
		},
		{
			name: "JWT with empty payload (minimal)",
			rawJWT: buildJWT(
				map[string]any{"alg": "none"},
				map[string]any{},
			),
			wantExpiry: false,
			wantIat:    false,
			wantErr:    false,
		},
		{
			name:    "empty JWT string",
			rawJWT:  "",
			wantErr: true,
		},
		{
			name:    "whitespace-only JWT string",
			rawJWT:  "   ",
			wantErr: true,
		},
		{
			name:    "JWT with wrong segment count (2 segments)",
			rawJWT:  "header.payload",
			wantErr: true,
		},
		{
			name:    "JWT with wrong segment count (4 segments)",
			rawJWT:  "a.b.c.d",
			wantErr: true,
		},
		{
			name:    "JWT with invalid base64 in payload",
			rawJWT:  "eyJhbGciOiJFUzI1NiJ9.!!!invalid!!!.sig",
			wantErr: true,
		},
		{
			name: "JWT with invalid JSON in payload",
			rawJWT: base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`)) +
				"." + base64.RawURLEncoding.EncodeToString([]byte(`{not-json`)) +
				".sig",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ParseJWTCredential(tt.rawJWT)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.wantExpiry && !parsed.HasExpiry() {
				t.Errorf("expected expiry to be set")
			}
			if !tt.wantExpiry && parsed.HasExpiry() {
				t.Errorf("expected no expiry, got %v", parsed.Expiry)
			}
			if tt.wantIat && parsed.IssuedAt.IsZero() {
				t.Errorf("expected IssuedAt to be set")
			}
			if !tt.wantIat && !parsed.IssuedAt.IsZero() {
				t.Errorf("expected no IssuedAt, got %v", parsed.IssuedAt)
			}
		})
	}
}

func TestParsedCredential_IsExpired(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name    string
		expiry  time.Time
		refTime time.Time
		want    bool
	}{
		{
			name:    "not expired - expiry in the future",
			expiry:  now.Add(1 * time.Hour),
			refTime: now,
			want:    false,
		},
		{
			name:    "expired - expiry in the past",
			expiry:  now.Add(-1 * time.Hour),
			refTime: now,
			want:    true,
		},
		{
			name:    "not expired - no expiry set (zero value)",
			expiry:  time.Time{},
			refTime: now,
			want:    false,
		},
		{
			name:    "expired - exactly at expiry boundary",
			expiry:  now,
			refTime: now.Add(1 * time.Second),
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pc := &ParsedCredential{Expiry: tt.expiry}
			if got := pc.IsExpired(tt.refTime); got != tt.want {
				t.Errorf("IsExpired(%v) = %v, want %v", tt.refTime, got, tt.want)
			}
		})
	}
}

func TestParsedCredential_HasExpiry(t *testing.T) {
	tests := []struct {
		name   string
		expiry time.Time
		want   bool
	}{
		{
			name:   "has expiry",
			expiry: time.Now().Add(1 * time.Hour),
			want:   true,
		},
		{
			name:   "no expiry (zero value)",
			expiry: time.Time{},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pc := &ParsedCredential{Expiry: tt.expiry}
			if got := pc.HasExpiry(); got != tt.want {
				t.Errorf("HasExpiry() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseJWTCredential_RawJWTPreserved(t *testing.T) {
	jwt := buildJWT(
		map[string]any{"alg": "ES256"},
		map[string]any{ClaimExp: float64(time.Now().Add(1 * time.Hour).Unix())},
	)

	parsed, err := ParseJWTCredential(jwt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if parsed.RawJWT != jwt {
		t.Errorf("RawJWT not preserved: got %q, want %q", parsed.RawJWT, jwt)
	}
}

func TestParseJWTCredential_IgnoresNonExpiryFields(t *testing.T) {
	// The parser should not fail when extra claims (iss, sub, vc, etc.) are
	// present — it simply ignores them and only extracts exp and iat.
	jwt := buildJWT(
		map[string]any{"alg": "ES256", "typ": "JWT", "kid": "key-1"},
		map[string]any{
			ClaimExp: float64(time.Now().Add(1 * time.Hour).Unix()),
			ClaimIat: float64(time.Now().Unix()),
			"iss":    "https://issuer.example.com",
			"sub":    "did:example:holder123",
			"jti":    "urn:uuid:abc-123",
			"vc": map[string]any{
				"type": []any{"VerifiableCredential"},
			},
		},
	)

	parsed, err := ParseJWTCredential(jwt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !parsed.HasExpiry() {
		t.Error("expected expiry to be set")
	}
	if parsed.IssuedAt.IsZero() {
		t.Error("expected IssuedAt to be set")
	}
}

func TestExtractTimeClaim_EdgeCases(t *testing.T) {
	tests := []struct {
		name   string
		claims map[string]any
		key    string
		isZero bool
	}{
		{
			name:   "missing claim",
			claims: map[string]any{},
			key:    ClaimExp,
			isZero: true,
		},
		{
			name:   "zero timestamp",
			claims: map[string]any{ClaimExp: float64(0)},
			key:    ClaimExp,
			isZero: true,
		},
		{
			name:   "negative timestamp",
			claims: map[string]any{ClaimExp: float64(-1)},
			key:    ClaimExp,
			isZero: true,
		},
		{
			name:   "string instead of number",
			claims: map[string]any{ClaimExp: "not-a-number"},
			key:    ClaimExp,
			isZero: true,
		},
		{
			name:   "valid timestamp",
			claims: map[string]any{ClaimExp: float64(1700000000)},
			key:    ClaimExp,
			isZero: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractTimeClaim(tt.claims, tt.key)
			if tt.isZero && !result.IsZero() {
				t.Errorf("expected zero time, got %v", result)
			}
			if !tt.isZero && result.IsZero() {
				t.Errorf("expected non-zero time, got zero")
			}
		})
	}
}

func TestExtractVCClaim(t *testing.T) {
	vc := map[string]any{
		"type":              []any{"VerifiableCredential", "MembershipCredential"},
		"issuer":            "did:web:example.org",
		"credentialSubject": map[string]any{"id": "did:web:example.org"},
	}
	jwt := buildJWT(map[string]any{"alg": "ES256", "kid": "did:web:example.org#key-1"},
		map[string]any{"iss": "did:web:example.org", "exp": 1893456000, "vc": vc})

	got, err := ExtractVCClaim(jwt)
	if err != nil {
		t.Fatalf("ExtractVCClaim() returned %v", err)
	}

	// The result has to be the credential object itself, not the enclosing JWT
	// claims: a credential store indexes the object.
	var decoded map[string]any
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatalf("the extracted claim is not valid JSON: %v", err)
	}
	if _, unexpected := decoded["iss"]; unexpected {
		t.Errorf("extracted the JWT claims instead of the vc object: %s", got)
	}
	if decoded["issuer"] != "did:web:example.org" {
		t.Errorf("issuer = %v, want did:web:example.org", decoded["issuer"])
	}
	types, ok := decoded["type"].([]any)
	if !ok || len(types) != 2 {
		t.Errorf("type = %v, want the two-element array", decoded["type"])
	}
}

func TestExtractVCClaimErrors(t *testing.T) {
	tests := map[string]string{
		"not a jwt":        "only-two.segments",
		"no vc claim":      buildJWT(map[string]any{"alg": "ES256"}, map[string]any{"iss": "did:web:example.org"}),
		"bad base64":       "aaa.!!!not-base64!!!.sig",
		"empty":            "",
		"payload not json": "aaa." + base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".sig",
	}
	for name, jwt := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ExtractVCClaim(jwt); err == nil {
				t.Error("ExtractVCClaim() returned nil, want an error")
			}
		})
	}
}
