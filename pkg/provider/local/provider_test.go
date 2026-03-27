package local

import (
	"context"
	"crypto/rsa"
	"errors"
	"net/url"
	"testing"

	// Packages
	authcrypto "github.com/djthorpe/go-auth/pkg/crypto"
	providerpkg "github.com/djthorpe/go-auth/pkg/provider"
	jwt "github.com/golang-jwt/jwt/v5"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

type assertErr string

func (e assertErr) Error() string {
	return string(e)
}

type stubCodec struct {
	issuer    string
	issuerErr error
	signed    string
	signErr   error
	claims    map[string]any
	verifyErr error
}

func (s stubCodec) Issuer() (string, error) {
	if s.issuerErr != nil {
		return "", s.issuerErr
	}
	return s.issuer, nil
}

func (s stubCodec) Sign(_ jwt.Claims) (string, error) {
	if s.signErr != nil {
		return "", s.signErr
	}
	return s.signed, nil
}

func (s stubCodec) Verify(_, _ string) (map[string]any, error) {
	if s.verifyErr != nil {
		return nil, s.verifyErr
	}
	return s.claims, nil
}

func testConfig(t *testing.T) (string, *rsa.PrivateKey) {
	t.Helper()
	key, err := authcrypto.GeneratePrivateKey()
	require.NoError(t, err)
	return "http://localhost:8084/api", key
}

func TestProviderBeginAuthorization(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	issuer, privateKey := testConfig(t)
	localProvider, err := New(issuer, privateKey)
	require.NoError(err)

	resp, err := localProvider.BeginAuthorization(context.Background(), providerpkg.AuthorizationRequest{
		ClientID:    "manager",
		RedirectURL: "http://127.0.0.1:8085/callback",
		ProviderURL: "/auth/provider/local",
		State:       "state-123",
		LoginHint:   "local@example.com",
	})
	require.NoError(err)
	uri, err := url.Parse(resp.RedirectURL)
	require.NoError(err)
	assert.Equal("/auth/provider/local", uri.Path)
	assert.Equal("manager", uri.Query().Get("client_id"))
	assert.Equal("state-123", uri.Query().Get("state"))
	assert.Equal("local@example.com", uri.Query().Get("login_hint"))
}

func TestProviderAccessors(t *testing.T) {
	issuer, privateKey := testConfig(t)
	provider, err := New(issuer, privateKey)
	require.NoError(t, err)

	require.Equal(t, "local", provider.Key())
	require.Equal(t, "http://localhost:8084/api", provider.PublicConfig().Issuer)

	var nilProvider *Provider
	handler, spec := nilProvider.HTTPHandler()
	require.Nil(t, handler)
	require.Nil(t, spec)
}

func TestProviderBeginAuthorizationValidation(t *testing.T) {
	issuer, privateKey := testConfig(t)
	provider, err := New(issuer, privateKey)
	require.NoError(t, err)

	tests := []struct {
		name string
		req  providerpkg.AuthorizationRequest
		err  string
	}{
		{name: "missing client id", req: providerpkg.AuthorizationRequest{ProviderURL: "/auth/provider/local", RedirectURL: "http://127.0.0.1/callback", State: "state"}, err: "client_id is required"},
		{name: "missing provider url", req: providerpkg.AuthorizationRequest{ClientID: "manager", RedirectURL: "http://127.0.0.1/callback", State: "state"}, err: "provider_url is required"},
		{name: "missing redirect url", req: providerpkg.AuthorizationRequest{ClientID: "manager", ProviderURL: "/auth/provider/local", State: "state"}, err: "redirect_url is required"},
		{name: "missing state", req: providerpkg.AuthorizationRequest{ClientID: "manager", ProviderURL: "/auth/provider/local", RedirectURL: "http://127.0.0.1/callback"}, err: "state is required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := provider.BeginAuthorization(context.Background(), tt.req)
			require.EqualError(t, err, tt.err)
		})
	}
}

func TestProviderBeginAuthorizationIncludesOptionalValues(t *testing.T) {
	issuer, privateKey := testConfig(t)
	provider, err := New(issuer, privateKey)
	require.NoError(t, err)

	resp, err := provider.BeginAuthorization(context.Background(), providerpkg.AuthorizationRequest{
		ClientID:            "manager",
		RedirectURL:         "http://127.0.0.1:8085/callback",
		ProviderURL:         "/auth/provider/local?foo=bar",
		State:               "state-123",
		Scopes:              []string{"openid", "email"},
		Nonce:               "nonce-123",
		CodeChallenge:       "challenge-123",
		CodeChallengeMethod: "S256",
		LoginHint:           "local@example.com",
	})
	require.NoError(t, err)

	uri, err := url.Parse(resp.RedirectURL)
	require.NoError(t, err)
	query := uri.Query()
	require.Equal(t, "bar", query.Get("foo"))
	require.Equal(t, "nonce-123", query.Get("nonce"))
	require.Equal(t, "challenge-123", query.Get("code_challenge"))
	require.Equal(t, "S256", query.Get("code_challenge_method"))
	require.Equal(t, "openid email", query.Get("scope"))
}

func TestExchangeAuthorizationCodeErrors(t *testing.T) {
	tests := []struct {
		name     string
		provider *Provider
		req      providerpkg.ExchangeRequest
		err      string
	}{
		{
			name:     "missing code",
			provider: &Provider{key: "local", codec: stubCodec{}},
			req:      providerpkg.ExchangeRequest{},
			err:      "code is required",
		},
		{
			name:     "issuer error",
			provider: &Provider{key: "local", codec: stubCodec{issuerErr: errors.New("issuer failure")}},
			req:      providerpkg.ExchangeRequest{Code: "code"},
			err:      "issuer failure",
		},
		{
			name:     "verify error",
			provider: &Provider{key: "local", codec: stubCodec{issuer: "issuer", verifyErr: errors.New("verify failure")}},
			req:      providerpkg.ExchangeRequest{Code: "code"},
			err:      "verify failure",
		},
		{
			name:     "missing client id",
			provider: &Provider{key: "local", codec: stubCodec{issuer: "issuer", claims: map[string]any{"typ": localAuthorizationCodeType, "redirect_uri": "http://127.0.0.1/callback"}}},
			req:      providerpkg.ExchangeRequest{Code: "code", RedirectURL: "http://127.0.0.1/callback"},
			err:      "authorization code missing client_id",
		},
		{
			name:     "nonce mismatch",
			provider: &Provider{key: "local", codec: stubCodec{issuer: "issuer", claims: map[string]any{"typ": localAuthorizationCodeType, "aud": "manager", "redirect_uri": "http://127.0.0.1/callback", "email": "local@example.com", "nonce": "actual"}}},
			req:      providerpkg.ExchangeRequest{Code: "code", RedirectURL: "http://127.0.0.1/callback", Nonce: "expected"},
			err:      "token nonce mismatch",
		},
		{
			name:     "missing email",
			provider: &Provider{key: "local", codec: stubCodec{issuer: "issuer", claims: map[string]any{"typ": localAuthorizationCodeType, "aud": "manager", "redirect_uri": "http://127.0.0.1/callback"}}},
			req:      providerpkg.ExchangeRequest{Code: "code", RedirectURL: "http://127.0.0.1/callback"},
			err:      "authorization code missing email",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.provider.ExchangeAuthorizationCode(context.Background(), tt.req)
			require.EqualError(t, err, tt.err)
		})
	}
}

func TestValidateAuthorizationCodeClaimsPKCE(t *testing.T) {
	t.Run("invalid type", func(t *testing.T) {
		err := validateAuthorizationCodeClaims(map[string]any{
			"typ":          "wrong",
			"aud":          "manager",
			"redirect_uri": "http://127.0.0.1/callback",
		}, "manager", "http://127.0.0.1/callback", "", "")
		require.EqualError(t, err, "invalid local authorization code")
	})

	t.Run("client id mismatch", func(t *testing.T) {
		err := validateAuthorizationCodeClaims(map[string]any{
			"typ":          localAuthorizationCodeType,
			"aud":          "other",
			"redirect_uri": "http://127.0.0.1/callback",
		}, "manager", "http://127.0.0.1/callback", "", "")
		require.EqualError(t, err, "authorization code client_id mismatch")
	})

	t.Run("redirect uri mismatch", func(t *testing.T) {
		err := validateAuthorizationCodeClaims(map[string]any{
			"typ":          localAuthorizationCodeType,
			"aud":          "manager",
			"redirect_uri": "http://127.0.0.1/other",
		}, "manager", "http://127.0.0.1/callback", "", "")
		require.EqualError(t, err, "authorization code redirect_uri mismatch")
	})

	t.Run("missing verifier", func(t *testing.T) {
		err := validateAuthorizationCodeClaims(map[string]any{
			"typ":            localAuthorizationCodeType,
			"aud":            "manager",
			"redirect_uri":   "http://127.0.0.1/callback",
			"code_challenge": "expected",
		}, "manager", "http://127.0.0.1/callback", "", "")
		require.EqualError(t, err, "code_verifier is required")
	})

	t.Run("plain success", func(t *testing.T) {
		err := validateAuthorizationCodeClaims(map[string]any{
			"typ":                   localAuthorizationCodeType,
			"aud":                   "manager",
			"redirect_uri":          "http://127.0.0.1/callback",
			"code_challenge":        "expected",
			"code_challenge_method": "plain",
		}, "manager", "http://127.0.0.1/callback", "expected", "")
		require.NoError(t, err)
	})

	t.Run("s256 success", func(t *testing.T) {
		err := validateAuthorizationCodeClaims(map[string]any{
			"typ":                   localAuthorizationCodeType,
			"aud":                   "manager",
			"redirect_uri":          "http://127.0.0.1/callback",
			"code_challenge":        "iMnq5o6zALKXGivsnlom_0F5_WYda32GHkxlV7mq7hQ",
			"code_challenge_method": "S256",
		}, "manager", "http://127.0.0.1/callback", "verifier", "")
		require.NoError(t, err)
	})

	t.Run("plain mismatch", func(t *testing.T) {
		err := validateAuthorizationCodeClaims(map[string]any{
			"typ":                   localAuthorizationCodeType,
			"aud":                   "manager",
			"redirect_uri":          "http://127.0.0.1/callback",
			"code_challenge":        "expected",
			"code_challenge_method": "plain",
		}, "manager", "http://127.0.0.1/callback", "actual", "")
		require.EqualError(t, err, "authorization code verifier mismatch")
	})

	t.Run("unsupported method", func(t *testing.T) {
		err := validateAuthorizationCodeClaims(map[string]any{
			"typ":                   localAuthorizationCodeType,
			"aud":                   "manager",
			"redirect_uri":          "http://127.0.0.1/callback",
			"code_challenge":        "expected",
			"code_challenge_method": "custom",
		}, "manager", "http://127.0.0.1/callback", "expected", "")
		require.EqualError(t, err, `unsupported code_challenge_method "custom"`)
	})
}

func TestNormalizeEmailAndName(t *testing.T) {
	assert.Equal(t, "local@example.com", mustNormalizeEmail(t, " LOCAL@EXAMPLE.COM "))
	assert.Equal(t, "local", nameFromEmail("local@example.com"))
	assert.Equal(t, "Local User", nameFromEmail("invalid"))

	_, err := normalizeEmail("bad")
	require.EqualError(t, err, "login_hint must be a valid email address")
}

func mustNormalizeEmail(t *testing.T, value string) string {
	t.Helper()
	email, err := normalizeEmail(value)
	require.NoError(t, err)
	return email
}
