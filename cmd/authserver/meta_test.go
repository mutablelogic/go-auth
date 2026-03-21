package main

import (
	"testing"

	// Packages
	kong "github.com/alecthomas/kong"
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
	require "github.com/stretchr/testify/require"
)

func TestUserUpdateMetaParse(t *testing.T) {
	var cli CLI
	parser, err := kong.New(&cli, kong.Name("authserver"))
	require.NoError(t, err)

	_, err = parser.Parse([]string{"user-update", "11111111-1111-1111-1111-111111111111", "--meta", "a=b;c=d"})
	require.NoError(t, err)
	require.Equal(t, map[string]any{"a": "b", "c": "d"}, cli.UserCommands.UpdateUser.Meta.Map())
}

func TestUserUpdateMetaParseJSONValues(t *testing.T) {
	var cli CLI
	parser, err := kong.New(&cli, kong.Name("authserver"))
	require.NoError(t, err)

	_, err = parser.Parse([]string{"user-update", "11111111-1111-1111-1111-111111111111", "--meta", `a=true;b=false;c=null;d=2`})
	require.NoError(t, err)
	require.Equal(t, map[string]any{"a": true, "b": false, "c": nil, "d": float64(2)}, cli.UserCommands.UpdateUser.Meta.Map())
}

func TestGroupUpdateMetaParse(t *testing.T) {
	var cli CLI
	parser, err := kong.New(&cli, kong.Name("authserver"))
	require.NoError(t, err)

	_, err = parser.Parse([]string{"group-update", "admins", "--meta", `{"team":"platform","priority":1}`})
	require.NoError(t, err)
	require.Equal(t, map[string]any{"team": "platform", "priority": float64(1)}, cli.GroupCommands.UpdateGroup.Meta.Map())
}

func TestOIDCCommandParseDefaultProvider(t *testing.T) {
	var cli CLI
	parser, err := kong.New(&cli, kong.Name("authserver"))
	require.NoError(t, err)

	_, err = parser.Parse([]string{"oidc"})
	require.NoError(t, err)
	require.Equal(t, "", cli.AuthCommands.OIDCConfig.Provider)
}

func TestOIDCCommandParseProvider(t *testing.T) {
	var cli CLI
	parser, err := kong.New(&cli, kong.Name("authserver"))
	require.NoError(t, err)

	_, err = parser.Parse([]string{"oidc", "google"})
	require.NoError(t, err)
	require.Equal(t, "google", cli.AuthCommands.OIDCConfig.Provider)
}

func TestLoginCommandParseProvider(t *testing.T) {
	var cli CLI
	parser, err := kong.New(&cli, kong.Name("authserver"))
	require.NoError(t, err)

	_, err = parser.Parse([]string{"login", "google"})
	require.NoError(t, err)
	require.Equal(t, "google", cli.AuthCommands.Login.Provider)
	require.Equal(t, defaultOIDCRedirectURL, cli.AuthCommands.Login.RedirectURL)
}

func TestLoginCommandParseLocalProvider(t *testing.T) {
	var cli CLI
	parser, err := kong.New(&cli, kong.Name("authserver"))
	require.NoError(t, err)

	_, err = parser.Parse([]string{"login", oidc.OAuthClientKeyLocal})
	require.NoError(t, err)
	require.Equal(t, oidc.OAuthClientKeyLocal, cli.AuthCommands.Login.Provider)
	require.Equal(t, defaultOIDCRedirectURL, cli.AuthCommands.Login.RedirectURL)
}

func TestOIDCIssuerForProviderDefaultsToLocal(t *testing.T) {
	issuer, err := oidcIssuerForProvider(oidc.PublicClientConfigurations{
		oidc.OAuthClientKeyLocal: {Issuer: "https://issuer.example.test/api", Provider: "oauth"},
		"google":                 {Issuer: oidc.GoogleIssuer, Provider: "oauth"},
	}, "")
	require.NoError(t, err)
	require.Equal(t, "https://issuer.example.test/api", issuer)
}

func TestOIDCIssuerForProviderReturnsNamedProvider(t *testing.T) {
	issuer, err := oidcIssuerForProvider(oidc.PublicClientConfigurations{
		oidc.OAuthClientKeyLocal: {Issuer: "https://issuer.example.test/api", Provider: "oauth"},
		"google":                 {Issuer: oidc.GoogleIssuer, Provider: "oauth"},
	}, "google")
	require.NoError(t, err)
	require.Equal(t, oidc.GoogleIssuer, issuer)
}

func TestOIDCIssuerForProviderUnknownProvider(t *testing.T) {
	_, err := oidcIssuerForProvider(oidc.PublicClientConfigurations{
		oidc.OAuthClientKeyLocal: {Issuer: "https://issuer.example.test/api", Provider: "oauth"},
		"google":                 {Issuer: oidc.GoogleIssuer, Provider: "oauth"},
	}, "github")
	require.EqualError(t, err, `unknown auth provider "github" (available: google, local)`)
}
