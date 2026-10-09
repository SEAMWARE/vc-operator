package oid4vci

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// maxCredentialResponseBytes is the maximum size of a credential response body
// to prevent excessive memory allocation.
const maxCredentialResponseBytes = 1 << 20 // 1 MiB

// Proof-of-possession JWT claim names.
const (
	// ClaimNonce is the JWT claim name for the c_nonce value.
	ClaimNonce = "nonce"

	// ClaimIssuedAt is the standard JWT "iat" claim name.
	ClaimIssuedAt = "iat"

	// ClaimAudience is the standard JWT "aud" claim name.
	ClaimAudience = "aud"
)

// RequestCredential sends a credential issuance request to the given credential endpoint.
// The request is authenticated with the provided access token (Bearer scheme).
//
// The CredentialRequest must include a proof-of-possession (typically generated via
// GenerateProofJWT). The method returns the parsed credential response or an error
// if the request fails.
func (c *oid4vciClient) RequestCredential(ctx context.Context, credentialURL string, accessToken string, request CredentialRequest) (*CredentialResponse, error) {
	logger := log.FromContext(ctx).WithName("oid4vci")

	logger.V(1).Info("Requesting credential",
		"credentialURL", credentialURL,
		"credentialConfigurationID", request.CredentialConfigurationID,
		"format", request.Format,
	)

	reqBody, err := json.Marshal(request)
	if err != nil {
		logger.Error(err, "Failed to marshal credential request")
		return nil, fmt.Errorf("%w: error marshaling request: %v", ErrCredentialRequest, err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, credentialURL, bytes.NewReader(reqBody))
	if err != nil {
		logger.Error(err, "Failed to create credential HTTP request", "credentialURL", credentialURL)
		return nil, fmt.Errorf("%w: %v", ErrCredentialRequest, err)
	}
	httpReq.Header.Set("Content-Type", ContentTypeJSON)
	httpReq.Header.Set("Accept", ContentTypeJSON)
	httpReq.Header.Set("Authorization", "Bearer "+accessToken)

	logger.V(1).Info("Sending credential request",
		"method", http.MethodPost,
		"url", credentialURL,
		"headers", httpReq.Header,
		"body", string(reqBody),
	)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		logger.Error(err, "Failed to execute credential request", "credentialURL", credentialURL)
		return nil, fmt.Errorf("%w: %v", ErrCredentialRequest, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		httpErr := parseHTTPError(resp)
		logger.Error(httpErr, "Credential endpoint returned non-OK status",
			"credentialURL", credentialURL,
			"statusCode", resp.StatusCode,
		)
		return nil, fmt.Errorf("%w: %v", ErrCredentialRequest, httpErr)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCredentialResponseBytes))
	if err != nil {
		logger.Error(err, "Failed to read credential response body", "credentialURL", credentialURL)
		return nil, fmt.Errorf("%w: error reading response body: %v", ErrCredentialRequest, err)
	}

	logger.V(1).Info("Received credential response",
		"statusCode", resp.StatusCode,
		"contentLength", len(body),
		"body", string(body),
	)

	var credResp CredentialResponse
	if err := json.Unmarshal(body, &credResp); err != nil {
		logger.Error(err, "Failed to parse credential response JSON", "credentialURL", credentialURL, "bodyLength", len(body))
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}

	logger.Info("Successfully received credential",
		"format", credResp.Format,
		"hasCNonce", credResp.CNonce != "",
	)

	return &credResp, nil
}

// nonceResponse is the JSON body returned by the OID4VCI nonce endpoint.
type nonceResponse struct {
	CNonce          string `json:"c_nonce"`
	CNonceExpiresIn int    `json:"c_nonce_expires_in,omitempty"`
}

// FetchNonce obtains a fresh c_nonce from the issuer's nonce endpoint.
// The nonce endpoint is advertised in the issuer metadata (OID4VCI draft 15+/Keycloak 26.x)
// and returns a nonce that must be included in proof-of-possession JWTs.
func (c *oid4vciClient) FetchNonce(ctx context.Context, nonceEndpoint, accessToken string) (string, error) {
	logger := log.FromContext(ctx).WithName("oid4vci")

	logger.V(1).Info("Fetching nonce from nonce endpoint", "nonceEndpoint", nonceEndpoint)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, nonceEndpoint, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create nonce request: %w", err)
	}
	httpReq.Header.Set("Accept", ContentTypeJSON)
	if accessToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+accessToken)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("failed to fetch nonce: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		httpErr := parseHTTPError(resp)
		logger.Error(httpErr, "Nonce endpoint returned non-OK status",
			"nonceEndpoint", nonceEndpoint,
			"statusCode", resp.StatusCode,
		)
		return "", fmt.Errorf("nonce endpoint error: %w", httpErr)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCredentialResponseBytes))
	if err != nil {
		return "", fmt.Errorf("failed to read nonce response: %w", err)
	}

	var nonceResp nonceResponse
	if err := json.Unmarshal(body, &nonceResp); err != nil {
		return "", fmt.Errorf("failed to parse nonce response: %w", err)
	}

	if nonceResp.CNonce == "" {
		return "", fmt.Errorf("nonce endpoint returned empty c_nonce")
	}

	logger.V(1).Info("Successfully fetched nonce",
		"nonceEndpoint", nonceEndpoint,
		"expiresIn", nonceResp.CNonceExpiresIn,
	)

	return nonceResp.CNonce, nil
}

// GenerateProofJWT creates a proof-of-possession JWT for a credential request.
// The JWT is signed with the provided ECDSA private key and includes:
//   - Header: alg=ES256, typ=openid4vci-proof+jwt, jwk=<public key> (or kid=<holderDID>)
//   - Claims: aud=<issuerURL>, iat=<now>, nonce=<cNonce>
//
// The issuerURL should be the credential issuer identifier (from metadata).
// The cNonce is the nonce value received from the token endpoint response.
// If holderDID is non-empty, the JWT uses a "kid" header with the DID URL
// instead of embedding the full JWK, enabling DID-based holder binding.
func GenerateProofJWT(privateKey *ecdsa.PrivateKey, issuerURL string, cNonce string, holderDID string) (string, error) {
	packageLogger.V(1).Info("Generating proof-of-possession JWT",
		"audience", issuerURL,
		"algorithm", ProofAlgorithmES256,
		"curve", privateKey.Curve.Params().Name,
		"holderDID", holderDID,
	)

	now := time.Now()

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		ClaimAudience: issuerURL,
		ClaimIssuedAt: now.Unix(),
		ClaimNonce:    cNonce,
	})

	token.Header["typ"] = JWTProofHeaderType

	if holderDID != "" {
		token.Header["kid"] = holderDID
	} else {
		jwk, err := buildJWKFromPublicKey(&privateKey.PublicKey)
		if err != nil {
			packageLogger.Error(err, "Failed to encode the public key as JWK", "audience", issuerURL)
			return "", fmt.Errorf("%w: %v", ErrProofGeneration, err)
		}
		token.Header["jwk"] = jwk
	}

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		packageLogger.Error(err, "Failed to sign proof-of-possession JWT", "audience", issuerURL)
		return "", fmt.Errorf("%w: %v", ErrProofGeneration, err)
	}

	packageLogger.V(1).Info("Successfully generated proof-of-possession JWT", "audience", issuerURL)
	return signedToken, nil
}

// buildJWKFromPublicKey constructs a JWK (JSON Web Key) representation
// of an ECDSA P-256 public key for inclusion in the JWT header.
func buildJWKFromPublicKey(pub *ecdsa.PublicKey) (map[string]any, error) {
	// uncompressed point encoding: 0x04 || X || Y, each coordinate coordByteLength bytes long
	point, err := pub.Bytes()
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(point[1 : 1+coordByteLength]),
		"y":   base64.RawURLEncoding.EncodeToString(point[1+coordByteLength:]),
	}, nil
}

// coordByteLength is the byte length of an ECDSA P-256 coordinate (32 bytes for a 256-bit curve).
const coordByteLength = 32

// VerifyProofJWT verifies and parses a proof-of-possession JWT.
// This is primarily useful for testing. It extracts the public key
// from the JWT's jwk header and verifies the signature.
func VerifyProofJWT(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		jwkRaw, ok := token.Header["jwk"]
		if !ok {
			return nil, fmt.Errorf("missing jwk header")
		}

		jwkMap, ok := jwkRaw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("invalid jwk header format")
		}

		return parseJWKToPublicKey(jwkMap)
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims type")
	}

	return claims, nil
}

// parseJWKToPublicKey reconstructs an ECDSA public key from a JWK map.
func parseJWKToPublicKey(jwk map[string]any) (*ecdsa.PublicKey, error) {
	xStr, ok := jwk["x"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid x coordinate")
	}
	yStr, ok := jwk["y"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid y coordinate")
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(xStr)
	if err != nil {
		return nil, fmt.Errorf("invalid x coordinate encoding: %v", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(yStr)
	if err != nil {
		return nil, fmt.Errorf("invalid y coordinate encoding: %v", err)
	}

	if len(xBytes) > coordByteLength || len(yBytes) > coordByteLength {
		return nil, fmt.Errorf("invalid coordinate length")
	}

	// uncompressed point encoding: 0x04 || X || Y, each coordinate left-padded to coordByteLength
	point := make([]byte, 1+2*coordByteLength)
	point[0] = 4
	copy(point[1+coordByteLength-len(xBytes):1+coordByteLength], xBytes)
	copy(point[len(point)-len(yBytes):], yBytes)

	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %v", err)
	}

	return pub, nil
}
