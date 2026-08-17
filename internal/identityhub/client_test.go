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

package identityhub

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	testDID     = "did:web:example.org"
	testDIDPath = "ZGlkOndlYjpleGFtcGxlLm9yZw"
	testAPIKey  = "c3VwZXItdXNlcg==.secret"
	testRawVC   = "header.payload.signature"
)

func testTarget(baseURL string) Target {
	return Target{
		BaseURL:       baseURL,
		ParticipantID: testDID,
		CredentialID:  "membership-credential",
		APIKey:        testAPIKey,
	}
}

func TestPublishPostsTheContainerToTheParticipantPath(t *testing.T) {
	var gotPath, gotKey, gotMethod string
	var gotBody credentialContainer

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotKey = r.Method, r.URL.Path, r.Header.Get(apiKeyHeader)
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decoding the request body: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	vc := json.RawMessage(`{"type":["VerifiableCredential"]}`)
	if err := NewClient().Publish(context.Background(), testTarget(server.URL), testRawVC, vc); err != nil {
		t.Fatalf("Publish() returned %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	// The participant id has to be base64url without padding: a raw DID in the
	// path is rejected as an illegal base64 character behind a bare 400.
	wantPath := "/participants/" + testDIDPath + "/credentials"
	if gotPath != wantPath {
		t.Errorf("path = %q, want %q", gotPath, wantPath)
	}
	if gotKey != testAPIKey {
		t.Errorf("api key header = %q, want %q", gotKey, testAPIKey)
	}
	if gotBody.ID != "membership-credential" || gotBody.ParticipantContextID != testDID {
		t.Errorf("unexpected envelope: %+v", gotBody)
	}
	if gotBody.Container.Format != formatJWT {
		t.Errorf("format = %q, want %q", gotBody.Container.Format, formatJWT)
	}
	if gotBody.Container.RawVC != testRawVC {
		t.Errorf("rawVc = %q, want %q", gotBody.Container.RawVC, testRawVC)
	}
	if string(gotBody.Container.Credential) != string(vc) {
		t.Errorf("credential = %s, want %s", gotBody.Container.Credential, vc)
	}
}

// A 409 is the normal outcome of a renewal: the stored copy is the one about to
// expire, and it has to be replaced rather than left in place.
// The replacement must never go through a delete: that would leave the
// IdentityHub holding no credential at all if the repost failed.
func TestPublishReplacesAnExistingCredentialInPlaceOnConflict(t *testing.T) {
	var calls []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		if r.Method == http.MethodPost && len(calls) == 1 {
			w.WriteHeader(http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	if err := NewClient().Publish(context.Background(), testTarget(server.URL), testRawVC, json.RawMessage(`{}`)); err != nil {
		t.Fatalf("Publish() returned %v", err)
	}

	want := []string{
		"POST /participants/" + testDIDPath + "/credentials",
		"PUT /participants/" + testDIDPath + "/credentials",
	}
	if len(calls) != len(want) {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Errorf("call %d = %q, want %q", i, calls[i], want[i])
		}
	}
}

// Older IdentityHub builds expose only POST on the credentials collection.
func TestPublishFallsBackToDeleteAndPostWhenPutIsUnsupported(t *testing.T) {
	for name, putStatus := range map[string]int{
		"method not allowed": http.StatusMethodNotAllowed,
		"route absent":       http.StatusNotFound,
	} {
		t.Run(name, func(t *testing.T) {
			var calls []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls = append(calls, r.Method+" "+r.URL.Path)
				switch {
				case r.Method == http.MethodPost && len(calls) == 1:
					w.WriteHeader(http.StatusConflict)
				case r.Method == http.MethodPut:
					w.WriteHeader(putStatus)
				default:
					w.WriteHeader(http.StatusNoContent)
				}
			}))
			defer server.Close()

			if err := NewClient().Publish(context.Background(), testTarget(server.URL), testRawVC, json.RawMessage(`{}`)); err != nil {
				t.Fatalf("Publish() returned %v", err)
			}

			want := []string{
				"POST /participants/" + testDIDPath + "/credentials",
				"PUT /participants/" + testDIDPath + "/credentials",
				"DELETE /participants/" + testDIDPath + "/credentials/membership-credential",
				"POST /participants/" + testDIDPath + "/credentials",
			}
			if len(calls) != len(want) {
				t.Fatalf("calls = %v, want %v", calls, want)
			}
			for i := range want {
				if calls[i] != want[i] {
					t.Errorf("call %d = %q, want %q", i, calls[i], want[i])
				}
			}
		})
	}
}

// On the legacy fallback the delete has already happened, so a failing repost
// leaves the IdentityHub with nothing. It must surface as an error, because the
// controller retrying the publication is what closes that window.
func TestPublishReportsAFailedRepostAfterTheDelete(t *testing.T) {
	posts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			posts++
			if posts == 1 {
				w.WriteHeader(http.StatusConflict)
				return
			}
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("identityhub restarting"))
		case http.MethodPut:
			w.WriteHeader(http.StatusMethodNotAllowed)
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()

	err := NewClient().Publish(context.Background(), testTarget(server.URL), testRawVC, json.RawMessage(`{}`))
	if err == nil {
		t.Fatal("Publish() returned nil, want the repost failure")
	}
	if !strings.Contains(err.Error(), "503") {
		t.Errorf("error = %q, want it to carry the repost status", err)
	}
}

// The goal of the delete is that the entry is gone, so an already-absent entry
// is not a failure.
func TestPublishToleratesANotFoundOnDelete(t *testing.T) {
	posts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			posts++
			if posts == 1 {
				w.WriteHeader(http.StatusConflict)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case http.MethodPut:
			w.WriteHeader(http.StatusMethodNotAllowed)
		case http.MethodDelete:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	if err := NewClient().Publish(context.Background(), testTarget(server.URL), testRawVC, json.RawMessage(`{}`)); err != nil {
		t.Fatalf("Publish() returned %v", err)
	}
	if posts != 2 {
		t.Errorf("posts = %d, want 2", posts)
	}
}

func TestPublishReportsTheStatusAndBodyOnFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`[{"message":"Invalid API token"}]`))
	}))
	defer server.Close()

	err := NewClient().Publish(context.Background(), testTarget(server.URL), testRawVC, json.RawMessage(`{}`))
	if err == nil {
		t.Fatal("Publish() returned nil, want an error")
	}
	if !strings.Contains(err.Error(), "401") || !strings.Contains(err.Error(), "Invalid API token") {
		t.Errorf("error = %q, want it to carry the status and the body", err)
	}
}

func TestPublishFailsWhenTheDeleteFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			w.WriteHeader(http.StatusConflict)
		case http.MethodPut:
			w.WriteHeader(http.StatusMethodNotAllowed)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	err := NewClient().Publish(context.Background(), testTarget(server.URL), testRawVC, json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "deleting credential") {
		t.Errorf("error = %v, want a delete failure", err)
	}
}

func TestPublishValidatesTheTarget(t *testing.T) {
	tests := map[string]Target{
		"missing url":            {ParticipantID: testDID, CredentialID: "c", APIKey: "k"},
		"missing participant id": {BaseURL: "http://ih", CredentialID: "c", APIKey: "k"},
		"missing credential id":  {BaseURL: "http://ih", ParticipantID: testDID, APIKey: "k"},
		"missing api key":        {BaseURL: "http://ih", ParticipantID: testDID, CredentialID: "c"},
	}
	for name, target := range tests {
		t.Run(name, func(t *testing.T) {
			if err := NewClient().Publish(context.Background(), target, testRawVC, json.RawMessage(`{}`)); err == nil {
				t.Error("Publish() returned nil, want a validation error")
			}
		})
	}
}

func TestCredentialsURLTrimsATrailingSlash(t *testing.T) {
	target := Target{BaseURL: "http://ih/api/identity/v1alpha/", ParticipantID: testDID}
	want := "http://ih/api/identity/v1alpha/participants/" + testDIDPath + "/credentials"
	if got := target.credentialsURL(); got != want {
		t.Errorf("credentialsURL() = %q, want %q", got, want)
	}
}
