package manager_test

import (
	"context"
	"crypto/rsa"
	"fmt"
	"testing"

	authcrypto "github.com/djthorpe/go-auth/pkg/crypto"
	manager "github.com/djthorpe/go-auth/pkg/manager"
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
	googleprovider "github.com/djthorpe/go-auth/pkg/provider/google"
	localprovider "github.com/djthorpe/go-auth/pkg/provider/local"
	schema "github.com/djthorpe/go-auth/schema"
	jwt "github.com/golang-jwt/jwt/v5"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
	attribute "go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	tracetest "go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestOIDCIssuerConfigured(t *testing.T) {
	mgr := newTestManagerWithOpts(t, manager.WithProvider(mustLocalProvider(t, "https://issuer.example.test/api")))

	issuer, err := mgr.OIDCIssuer()
	require.NoError(t, err)
	assert.Equal(t, "https://issuer.example.test/api", issuer)
}

func TestOIDCIssuerMissing(t *testing.T) {
	mgr := newTestManager(t)

	_, err := mgr.OIDCIssuer()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "issuer is not configured")
}

func TestOIDCIssuerMissingWithoutLocalProvider(t *testing.T) {
	mgr := newTestManagerWithOpts(t, mustGoogleProviderOpt(t, oidc.GoogleIssuer))

	_, err := mgr.OIDCIssuer()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "issuer is not configured")
}

func TestOIDCConfigUsesConfiguredIssuer(t *testing.T) {
	mgr := newTestManagerWithOpts(t, manager.WithProvider(mustLocalProvider(t, "https://issuer.example.test/api")))

	cfg, err := mgr.OIDCConfig(nil)
	require.NoError(t, err)
	assert.Equal(t, "https://issuer.example.test/api", cfg.Issuer)
	assert.Equal(t, oidc.AuthorizationURL("https://issuer.example.test/api"), cfg.AuthorizationEndpoint)
	assert.Equal(t, oidc.AuthCodeURL("https://issuer.example.test/api"), cfg.TokenEndpoint)
	assert.Equal(t, oidc.UserInfoURL("https://issuer.example.test/api"), cfg.UserInfoEndpoint)
	assert.Equal(t, oidc.JWKSURL("https://issuer.example.test/api"), cfg.JwksURI)
	assert.Equal(t, []string{oidc.ResponseTypeCode}, cfg.ResponseTypes)
	assert.Equal(t, []string{"authorization_code", "refresh_token"}, cfg.GrantTypesSupported)
	assert.Equal(t, []string{oidc.ScopeOpenID, oidc.ScopeEmail, oidc.ScopeProfile}, cfg.ScopesSupported)
	assert.Equal(t, []string{oidc.CodeChallengeMethodS256}, cfg.CodeChallengeMethods)
	assert.Contains(t, cfg.ClaimsSupported, "session")
}

func TestAuthConfigUsesPublicGoogleConfiguration(t *testing.T) {
	mgr := newTestManagerWithOpts(t,
		manager.WithProvider(mustLocalProvider(t, "https://issuer.example.test/api")),
		mustGoogleProviderOpt(t, oidc.GoogleIssuer),
	)

	cfg, err := mgr.AuthConfig()
	require.NoError(t, err)
	local, ok := cfg[schema.ProviderKeyLocal]
	require.True(t, ok)
	assert.Equal(t, "https://issuer.example.test/api", local.Issuer)
	assert.Equal(t, "", local.ClientID)
	google, ok := cfg["google"]
	require.True(t, ok)
	assert.Equal(t, oidc.GoogleIssuer, google.Issuer)
	assert.Equal(t, "google-client-id", google.ClientID)
}

func TestAuthConfigTracing(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	defer func() {
		require.NoError(t, provider.Shutdown(context.Background()))
	}()

	mgr := newTestManagerWithOpts(t,
		manager.WithTracer(provider.Tracer("manager-authconfig-test")),
		manager.WithProvider(mustLocalProvider(t, "https://issuer.example.test/api")),
		mustGoogleProviderOpt(t, oidc.GoogleIssuer),
	)

	config, err := mgr.AuthConfig()
	require.NoError(t, err)
	require.Len(t, config, 2)
	require.NoError(t, provider.ForceFlush(context.Background()))

	spans := exporter.GetSpans()
	var authConfigSpan *tracetest.SpanStub
	for i := range spans {
		if spans[i].Name == "manager.AuthConfig" {
			authConfigSpan = &spans[i]
			break
		}
	}
	require.NotNil(t, authConfigSpan)
	assert.Contains(t, authConfigSpan.Attributes, attribute.Int("provider_count", 2))
}

func TestAuthConfigRequiresConfiguredClients(t *testing.T) {
	mgr := newTestManager(t)

	_, err := mgr.AuthConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "providers")
}
func TestManagerOIDCVerifySuccessAndIssuerMismatch(t *testing.T) {
	key := mustRSAKey(t)
	mgr := newTestManagerWithOpts(t, manager.WithPrivateKey(key))

	token, err := mgr.OIDCSign(jwt.MapClaims{"iss": "https://issuer.example.test/api"})
	require.NoError(t, err)

	claims, err := mgr.OIDCVerify(token, "https://issuer.example.test/api")
	require.NoError(t, err)
	assert.Equal(t, "https://issuer.example.test/api", claims["iss"])

	_, err = mgr.OIDCVerify(token, "https://wrong.example.test/api")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "issuer")
}

func TestOIDCJWKSet(t *testing.T) {
	key := mustRSAKey(t)

	jwks, err := oidc.PublicJWKSet(key)
	require.NoError(t, err)

	require.Equal(t, 1, jwks.Len())
	entry, ok := jwks.LookupKeyID(oidc.KeyID)
	require.True(t, ok)
	alg, ok := entry.Get("alg")
	require.True(t, ok)
	assert.Equal(t, oidc.SigningAlgorithm, fmt.Sprint(alg))
}

func TestPublicJWKSetRequiresKey(t *testing.T) {
	_, err := oidc.PublicJWKSet(nil)
	require.Error(t, err)
}

func TestManagerOIDCSignRequiresKey(t *testing.T) {
	mgr := newTestManager(t)
	_, err := mgr.OIDCSign(jwt.MapClaims{"iss": "https://issuer.example.com"})
	require.Error(t, err)
}

func TestManagerOIDCJWKSetRequiresKey(t *testing.T) {
	mgr := newTestManager(t)
	_, err := mgr.OIDCJWKSet()
	require.Error(t, err)
}

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := authcrypto.GeneratePrivateKey()
	require.NoError(t, err)
	return key
}

func mustLocalProvider(t *testing.T, issuer string) *localprovider.Provider {
	t.Helper()
	provider, err := localprovider.New(issuer, mustRSAKey(t))
	require.NoError(t, err)
	return provider
}

func mustGoogleProviderOpt(t *testing.T, issuer string) manager.Opt {
	t.Helper()
	provider, err := googleprovider.NewWithIssuer("google-client-id", "google-client-secret", issuer)
	require.NoError(t, err)
	return manager.WithProvider(provider)
}
