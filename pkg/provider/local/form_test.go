package local

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	// Packages
	providerpkg "github.com/djthorpe/go-auth/pkg/provider"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestProviderHandlerRedirectsToCallback(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	issuer, privateKey := testConfig(t)
	localProvider, err := New(issuer, privateKey)
	require.NoError(err)
	handler, spec := localProvider.HTTPHandler()
	require.NotNil(handler)
	require.NotNil(spec)

	form := url.Values{}
	form.Set("client_id", "manager")
	form.Set("redirect_uri", "http://127.0.0.1:8085/callback")
	form.Set("state", "state-123")
	form.Set("login_hint", "local@example.com")
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
		Code:        uri.Query().Get("code"),
		RedirectURL: "http://127.0.0.1:8085/callback",
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
	handler, spec := localProvider.HTTPHandler()
	require.NotNil(handler)
	require.NotNil(spec)

	form := url.Values{}
	form.Set("client_id", "manager")
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

	getReq := httptest.NewRequest(http.MethodGet, "/auth/provider/local?client_id=manager&state=test&redirect_uri=http://127.0.0.1/callback", nil)
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

func TestProviderSubmitFormValidationErrors(t *testing.T) {
	issuer, privateKey := testConfig(t)
	provider, err := New(issuer, privateKey)
	require.NoError(t, err)

	t.Run("missing required fields", func(t *testing.T) {
		form := url.Values{}
		form.Set("client_id", "manager")
		form.Set("login_hint", "local@example.com")
		req := httptest.NewRequest(http.MethodPost, "/auth/provider/local", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		res := httptest.NewRecorder()

		provider.ServeHTTP(res, req)

		require.Equal(t, http.StatusOK, res.Code)
		require.Contains(t, res.Body.String(), "client_id, redirect_uri and state are required")
	})

	t.Run("invalid redirect uri", func(t *testing.T) {
		form := url.Values{}
		form.Set("client_id", "manager")
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
	form.Set("client_id", "manager")
	form.Set("state", "state-123")
	req := httptest.NewRequest(http.MethodPost, "/auth/provider/local", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	require.NoError(t, req.ParseForm())

	clone := requestWithFormAsQuery(req)

	require.Equal(t, req.URL.Path, clone.URL.Path)
	require.Equal(t, "manager", clone.URL.Query().Get("client_id"))
	require.Equal(t, "state-123", clone.URL.Query().Get("state"))
}
