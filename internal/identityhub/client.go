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

// Package identityhub publishes credentials into the credential store of an
// EDC IdentityHub.
//
// An IdentityHub keeps its own copy of the credentials a connector presents. It
// does not fetch them: the DCP credential-issuance protocol would let it, but
// that needs a DCP-compliant issuer service, and a Keycloak-issued credential
// arrives out of band. Publishing that copy on every issuance and renewal is
// what keeps the two in step - otherwise the IdentityHub goes on presenting a
// credential that expired, and DCP exchanges start failing with nothing having
// changed in the cluster.
package identityhub

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	// apiKeyHeader is the header the IdentityHub Identity API authenticates with.
	apiKeyHeader = "x-api-key"

	// formatJWT is the credential format identifier the IdentityHub uses for a
	// compact-serialized JWT credential. It is not the OID4VCI format name.
	formatJWT = "VC1_0_JWT"

	// defaultTimeout bounds a single request to the IdentityHub.
	defaultTimeout = 30 * time.Second
)

// Target identifies the credential store entry to publish to.
type Target struct {
	// BaseURL is the IdentityHub Identity API base URL including the version
	// segment, e.g. "http://identityhub-service:8082/api/identity/v1alpha".
	BaseURL string

	// ParticipantID is the participant context the credential belongs to, i.e.
	// the participant's DID.
	ParticipantID string

	// CredentialID is the id the credential is stored under. Publishing the
	// same id again replaces the stored copy.
	CredentialID string

	// APIKey is the composed IdentityHub api key,
	// base64(participantContextId).secret.
	APIKey string
}

// credentialContainer is the request body the credentials endpoint expects.
//
// Note the field name: the payload nests the credential under
// verifiableCredentialContainer, while the IdentityHub's own validation errors
// talk about "credential", which makes a wrong shape here look like a wrong
// credential.
type credentialContainer struct {
	ID                   string    `json:"id"`
	ParticipantContextID string    `json:"participantContextId"`
	Container            container `json:"verifiableCredentialContainer"`
}

type container struct {
	RawVC      string          `json:"rawVc"`
	Format     string          `json:"format"`
	Credential json.RawMessage `json:"credential"`
}

// Client publishes credentials into an IdentityHub credential store.
type Client struct {
	httpClient *http.Client
}

// NewClient returns a Client with a bounded per-request timeout.
func NewClient() *Client {
	return &Client{httpClient: &http.Client{Timeout: defaultTimeout}}
}

// NewClientWithHTTPClient returns a Client using the given http.Client, for
// tests and for callers that need their own transport.
func NewClientWithHTTPClient(httpClient *http.Client) *Client {
	if httpClient == nil {
		return NewClient()
	}
	return &Client{httpClient: httpClient}
}

// Publish stores the credential, replacing any copy already held under the same
// id.
//
// The credentials endpoint answers 409 when the id exists rather than
// overwriting, so the existing entry is deleted and the credential posted
// again. That path is the normal one on a renewal, and it is the whole point of
// publishing: the copy being replaced is the one about to expire.
func (c *Client) Publish(ctx context.Context, target Target, rawVC string, vc json.RawMessage) error {
	if err := target.validate(); err != nil {
		return err
	}

	body, err := json.Marshal(credentialContainer{
		ID:                   target.CredentialID,
		ParticipantContextID: target.ParticipantID,
		Container: container{
			RawVC:      strings.TrimSpace(rawVC),
			Format:     formatJWT,
			Credential: vc,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to build the credential container: %w", err)
	}

	endpoint := target.credentialsURL()

	status, respBody, err := c.do(ctx, http.MethodPost, endpoint, target.APIKey, body)
	if err != nil {
		return err
	}
	if status == http.StatusConflict {
		if err := c.delete(ctx, target); err != nil {
			return err
		}
		status, respBody, err = c.do(ctx, http.MethodPost, endpoint, target.APIKey, body)
		if err != nil {
			return err
		}
	}
	if !isSuccess(status) {
		return fmt.Errorf("publishing credential %q returned HTTP %d: %s", target.CredentialID, status, truncate(respBody))
	}

	return nil
}

// delete removes the stored credential. A 404 is not an error: the goal is that
// the entry is gone.
func (c *Client) delete(ctx context.Context, target Target) error {
	endpoint := fmt.Sprintf("%s/%s", target.credentialsURL(), target.CredentialID)
	status, body, err := c.do(ctx, http.MethodDelete, endpoint, target.APIKey, nil)
	if err != nil {
		return err
	}
	if !isSuccess(status) && status != http.StatusNotFound {
		return fmt.Errorf("deleting credential %q returned HTTP %d: %s", target.CredentialID, status, truncate(body))
	}
	return nil
}

func (c *Client) do(ctx context.Context, method, url, apiKey string, body []byte) (int, []byte, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to build the %s request: %w", method, err)
	}
	req.Header.Set(apiKeyHeader, apiKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%s %s failed: %w", method, url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("failed to read the response of %s %s: %w", method, url, err)
	}

	return resp.StatusCode, respBody, nil
}

// credentialsURL is the credential collection of the participant context. The
// participant id goes into the path base64url-encoded without padding; a raw
// DID there is rejected as an illegal base64 character behind a bare 400.
func (t Target) credentialsURL() string {
	encoded := base64.RawURLEncoding.EncodeToString([]byte(t.ParticipantID))
	return fmt.Sprintf("%s/participants/%s/credentials", strings.TrimSuffix(t.BaseURL, "/"), encoded)
}

func (t Target) validate() error {
	switch {
	case t.BaseURL == "":
		return fmt.Errorf("identityhub base URL is required")
	case t.ParticipantID == "":
		return fmt.Errorf("identityhub participant id is required")
	case t.CredentialID == "":
		return fmt.Errorf("identityhub credential id is required")
	case t.APIKey == "":
		return fmt.Errorf("identityhub api key is required")
	}
	return nil
}

func isSuccess(status int) bool {
	return status >= 200 && status < 300
}

// truncate keeps an error message readable when the IdentityHub answers with a
// long body, and avoids logging a whole page of HTML.
func truncate(body []byte) string {
	const max = 512
	s := strings.TrimSpace(string(body))
	if s == "" {
		return "<empty response>"
	}
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
