// Copyright 2026 David Thorpe
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package local

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	// Packages
	providerpkg "github.com/mutablelogic/go-auth/auth/provider"
	types "github.com/mutablelogic/go-server/pkg/types"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestProviderHandlerRedirectsToCallback(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	issuer, privateKey := testConfig(t)
	localProvider, err := New(issuer, privateKey)
	require.NoError(err)
	pathItem := localProvider.HTTPHandler()
	require.NotNil(pathItem)
	handler := pathItem.Handler()
	spec := pathItem.Spec("/auth/provider/local", nil)
	require.NotNil(handler)
	require.NotNil(spec)

	form := url.Values{}
	form.Set("redirect_uri", "http://127.0.0.1:8085/callback")
	form.Set("state", "state-123")
	form.Set("login_hint", "local@example.com")
	form.Set("code_challenge", codeChallengeForVerifier("verifier-123"))
	form.Set("code_challenge_method", "S256")
	req := httptest.NewRequest(http.MethodPost, "/auth/provider/local", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res := httptest.NewRecorder()

	handler(res, req)

	require.Equal(http.StatusFound, res.Code)
	location := res.Header().Get("Location")
	require.NotEmpty(location)
	uri, err := url.Parse(location)
	require.NoError(err)
	assert.Equal("127.0.0.1:8085", uri.Host)
	assert.Equal("state-123", uri.Query().Get("state"))
	assert.NotEmpty(uri.Query().Get("code"))

	identity, err := localProvider.ExchangeAuthorizationCode(context.Background(), providerpkg.ExchangeRequest{
		Code:         uri.Query().Get("code"),
		RedirectURL:  "http://127.0.0.1:8085/callback",
		CodeVerifier: "verifier-123",
	})
	require.NoError(err)
	assert.Equal("local", identity.Provider)
	assert.Equal("local@example.com", identity.Email)
	assert.Equal("local@example.com", identity.Sub)
}

func TestProviderHandlerRequiresEmail(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	issuer, privateKey := testConfig(t)
	localProvider, err := New(issuer, privateKey)
	require.NoError(err)
	pathItem := localProvider.HTTPHandler()
	require.NotNil(pathItem)
	handler := pathItem.Handler()
	spec := pathItem.Spec("/auth/provider/local", nil)
	require.NotNil(handler)
	require.NotNil(spec)

	form := url.Values{}
	form.Set("redirect_uri", "http://127.0.0.1:8085/callback")
	form.Set("state", "state-123")
	req := httptest.NewRequest(http.MethodPost, "/auth/provider/local", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res := httptest.NewRecorder()

	handler(res, req)

	require.Equal(http.StatusOK, res.Code)
	assert.Contains(res.Body.String(), "login_hint is required")
	assert.Contains(res.Body.String(), `<form method="post" action="/auth/provider/local">`)
}

func TestProviderServeHTTPGetAndMethodNotAllowed(t *testing.T) {
	issuer, privateKey := testConfig(t)
	provider, err := New(issuer, privateKey)
	require.NoError(t, err)

	getReq := httptest.NewRequest(http.MethodGet, "/auth/provider/local?state=test&redirect_uri=http://127.0.0.1/callback", nil)
	getRes := httptest.NewRecorder()
	provider.ServeHTTP(getRes, getReq)
	require.Equal(t, http.StatusOK, getRes.Code)
	require.Contains(t, getRes.Header().Get("Content-Type"), "text/html")
	require.Contains(t, getRes.Body.String(), "Local Issuer")

	badReq := httptest.NewRequest(http.MethodPut, "/auth/provider/local", nil)
	badRes := httptest.NewRecorder()
	provider.ServeHTTP(badRes, badReq)
	require.Equal(t, http.StatusMethodNotAllowed, badRes.Code)
}

func TestProviderHTTPHandlerSpec(t *testing.T) {
	issuer, privateKey := testConfig(t)
	provider, err := New(issuer, privateKey)
	require.NoError(t, err)

	pathItem := provider.HTTPHandler()
	require.NotNil(t, pathItem)
	spec := pathItem.Spec("/auth/provider/local", nil)
	require.NotNil(t, spec)
	require.NotNil(t, spec.Get)
	require.NotNil(t, spec.Post)

	if spec.Get.Summary != "Render local login form" {
		t.Fatalf("spec.Get.Summary = %q, want %q", spec.Get.Summary, "Render local login form")
	}
	if spec.Post.Summary != "Submit local login form" {
		t.Fatalf("spec.Post.Summary = %q, want %q", spec.Post.Summary, "Submit local login form")
	}
	if len(spec.Get.Parameters) == 0 {
		t.Fatal("expected GET operation to declare query parameters")
	}
	getHTML := spec.Get.Responses["200"].Content[types.ContentTypeHTML]
	if getHTML.Schema == nil {
		t.Fatal("expected GET 200 response to declare an HTML schema")
	}
	postForm := spec.Post.RequestBody.Content[types.ContentTypeForm]
	if postForm.Schema == nil {
		t.Fatal("expected POST operation to declare a form request schema")
	}
	if spec.Post.Responses["302"].Description == "" {
		t.Fatal("expected POST operation to declare a redirect response")
	}
	postHTML := spec.Post.Responses["200"].Content[types.ContentTypeHTML]
	if postHTML.Schema == nil {
		t.Fatal("expected POST 200 response to declare an HTML schema")
	}
}

func TestProviderSubmitFormValidationErrors(t *testing.T) {
	issuer, privateKey := testConfig(t)
	provider, err := New(issuer, privateKey)
	require.NoError(t, err)

	t.Run("missing required fields", func(t *testing.T) {
		form := url.Values{}
		form.Set("login_hint", "local@example.com")
		req := httptest.NewRequest(http.MethodPost, "/auth/provider/local", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		res := httptest.NewRecorder()

		provider.ServeHTTP(res, req)

		require.Equal(t, http.StatusOK, res.Code)
		require.Contains(t, res.Body.String(), "redirect_uri and state are required")
	})

	t.Run("invalid redirect uri", func(t *testing.T) {
		form := url.Values{}
		form.Set("redirect_uri", "://bad")
		form.Set("state", "state-123")
		form.Set("login_hint", "local@example.com")
		req := httptest.NewRequest(http.MethodPost, "/auth/provider/local", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		res := httptest.NewRecorder()

		provider.ServeHTTP(res, req)

		require.Equal(t, http.StatusOK, res.Code)
		require.Contains(t, res.Body.String(), "redirect_uri is invalid")
	})
}

func TestRequestWithFormAsQuery(t *testing.T) {
	form := url.Values{}
	form.Set("state", "state-123")
	req := httptest.NewRequest(http.MethodPost, "/auth/provider/local", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	require.NoError(t, req.ParseForm())

	clone := requestWithFormAsQuery(req)

	require.Equal(t, req.URL.Path, clone.URL.Path)
	require.Equal(t, "state-123", clone.URL.Query().Get("state"))
}
