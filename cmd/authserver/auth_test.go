package main

import (
	"errors"
	"net/url"
	"strings"
	"testing"

	// Packages
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
	"github.com/djthorpe/go-auth/pkg/webcallback"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestAuthorizationFlowOutput(t *testing.T) {
	flow := &oidc.AuthorizationCodeFlow{
		AuthorizationEndpoint: "https://accounts.example.test/o/oauth2/v2/auth",
		AuthorizationURL:      "https://accounts.example.test/o/oauth2/v2/auth?client_id=client-id&state=state-123",
		TokenEndpoint:         "https://accounts.example.test/token",
		ClientID:              "client-id",
		RedirectURL:           "http://127.0.0.1:8085/callback",
		ResponseType:          oidc.ResponseTypeCode,
		Scopes:                []string{oidc.ScopeOpenID, oidc.ScopeEmail, oidc.ScopeProfile},
		State:                 "state-123",
	}

	output, err := authorizationFlowOutput(flow)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(output, "Authorization URL:\nhttps://accounts.example.test/o/oauth2/v2/auth?client_id=client-id&state=state-123\n\n{"))
	assert.Contains(t, output, `"authorization_endpoint": "https://accounts.example.test/o/oauth2/v2/auth"`)
	assert.Contains(t, output, `"token_endpoint": "https://accounts.example.test/token"`)
}

func TestAuthorizationFlowOutputRequiresFlow(t *testing.T) {
	output, err := authorizationFlowOutput(nil)
	require.EqualError(t, err, "authorization flow is required")
	assert.Equal(t, "", output)
}

func TestOpenAuthorizationURL(t *testing.T) {
	original := openBrowserURL
	t.Cleanup(func() {
		openBrowserURL = original
	})

	t.Run("requires flow", func(t *testing.T) {
		err := openAuthorizationURL(nil)
		require.EqualError(t, err, "authorization flow is required")
	})

	t.Run("skips empty authorization url", func(t *testing.T) {
		called := false
		openBrowserURL = func(string) error {
			called = true
			return nil
		}

		err := openAuthorizationURL(&oidc.AuthorizationCodeFlow{})
		require.NoError(t, err)
		assert.False(t, called)
	})

	t.Run("opens authorization url", func(t *testing.T) {
		var gotURL string
		openBrowserURL = func(rawURL string) error {
			gotURL = rawURL
			return nil
		}

		err := openAuthorizationURL(&oidc.AuthorizationCodeFlow{AuthorizationURL: "https://example.com/auth"})
		require.NoError(t, err)
		assert.Equal(t, "https://example.com/auth", gotURL)
	})

	t.Run("wraps browser errors", func(t *testing.T) {
		openBrowserURL = func(string) error {
			return errors.New("boom")
		}

		err := openAuthorizationURL(&oidc.AuthorizationCodeFlow{AuthorizationURL: "https://example.com/auth"})
		require.EqualError(t, err, "open authorization URL: boom")
	})
}

func TestAuthorizationCodeFromCallback(t *testing.T) {
	flow := &oidc.AuthorizationCodeFlow{State: "state-123"}

	t.Run("requires flow", func(t *testing.T) {
		code, err := authorizationCodeFromCallback(nil, &webcallback.Result{})
		require.EqualError(t, err, "authorization flow is required")
		assert.Equal(t, "", code)
	})

	t.Run("requires result", func(t *testing.T) {
		code, err := authorizationCodeFromCallback(flow, nil)
		require.EqualError(t, err, "callback result is required")
		assert.Equal(t, "", code)
	})

	t.Run("requires matching state", func(t *testing.T) {
		code, err := authorizationCodeFromCallback(flow, &webcallback.Result{Query: url.Values{"state": {"wrong"}, "code": {"abc123"}}})
		require.EqualError(t, err, "callback state mismatch")
		assert.Equal(t, "", code)
	})

	t.Run("requires code", func(t *testing.T) {
		code, err := authorizationCodeFromCallback(flow, &webcallback.Result{Query: url.Values{"state": {"state-123"}}})
		require.EqualError(t, err, "callback code is required")
		assert.Equal(t, "", code)
	})

	t.Run("returns code", func(t *testing.T) {
		code, err := authorizationCodeFromCallback(flow, &webcallback.Result{Query: url.Values{"state": {"state-123"}, "code": {"abc123"}}})
		require.NoError(t, err)
		assert.Equal(t, "abc123", code)
	})
}
