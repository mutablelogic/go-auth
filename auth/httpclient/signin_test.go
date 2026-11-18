package httpclient_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	// Packages
	goauth "github.com/mutablelogic/go-auth"
	httpclient "github.com/mutablelogic/go-auth/auth/httpclient"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
	oauth2 "golang.org/x/oauth2"
)

func Test_SignInError(t *testing.T) {
	signIn := httpclient.SignIn{
		Server:     httpclient.ServerMetadata{Issuer: "https://accounts.google.com", AuthorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth"},
		ClientID:   "client",
		Scopes:     []string{"tasks"},
		Credential: "GOOGLE_TOKEN",
	}

	// The error says who to sign in with, is its error, and has how to sign
	// in, even when it's wrapped
	err := httpclient.NewSignInError(signIn, goauth.ErrForbidden.With("no grant"))
	assert.Equal(t, "forbidden: no grant: sign in with https://accounts.google.com", err.Error())
	assert.ErrorIs(t, err, goauth.ErrForbidden)
	got := httpclient.SignInOf(fmt.Errorf("volume: %w", err))
	require.NotNil(t, got)
	assert.Equal(t, signIn, *got)
	assert.Nil(t, httpclient.SignInOf(errors.New("other")))

	// It's JSON, without secrets, to return to a client
	data, err2 := json.Marshal(signIn)
	require.NoError(t, err2)
	assert.JSONEq(t, `{"server":{"issuer":"https://accounts.google.com","authorization_endpoint":"https://accounts.google.com/o/oauth2/v2/auth"},"client_id":"client","scopes":["tasks"],"credential":"GOOGLE_TOKEN"}`, string(data))
}

func Test_SignInCode(t *testing.T) {
	ctx := t.Context()

	// A token endpoint, which issues a token for the code, of its verifier,
	// with the client's secret, in the form
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		w.Header().Set("Content-Type", "application/json")
		if r.Form.Get("code") != "code" || r.Form.Get("code_verifier") != "verifier" || r.Form.Get("client_secret") != "secret" || r.Form.Get("redirect_uri") != "http://127.0.0.1:8085/callback" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"access","token_type":"Bearer","refresh_token":"refresh","expires_in":3600,"scope":"openid tasks"}`))
	}))
	defer server.Close()
	metadata := httpclient.ServerMetadata{Issuer: "https://issuer", AuthorizationEndpoint: "https://issuer/authorize", TokenEndpoint: server.URL}
	client := httpclient.Registration{ClientID: "client", ClientSecret: "secret"}

	// The URL to sign in at, with the challenge, and the options
	signIn := httpclient.SignIn{Server: metadata, ClientID: "client", Scopes: []string{"tasks"}}
	u, err := url.Parse(signIn.AuthCodeURL("http://127.0.0.1:8085/callback", "state", "verifier", oauth2.AccessTypeOffline))
	require.NoError(t, err)
	assert.Equal(t, "issuer", u.Host)
	query := u.Query()
	assert.Equal(t, "client", query.Get("client_id"))
	assert.Equal(t, "tasks", query.Get("scope"))
	assert.Equal(t, "state", query.Get("state"))
	assert.Equal(t, "S256", query.Get("code_challenge_method"))
	assert.Equal(t, oauth2.S256ChallengeFromVerifier("verifier"), query.Get("code_challenge"))
	assert.Equal(t, "offline", query.Get("access_type"))

	// The code is exchanged for a grant, with its tokens, and the scopes the
	// server granted, without the client's secret
	code := httpclient.SignInCode{Credential: "TOKEN", Code: "code", CodeVerifier: "verifier", RedirectURI: "http://127.0.0.1:8085/callback"}
	grant, err := httpclient.ExchangeCode(ctx, metadata, client, code)
	require.NoError(t, err)
	assert.Equal(t, "access", grant.Token.AccessToken)
	assert.Equal(t, "refresh", grant.Token.RefreshToken)
	assert.True(t, grant.Token.Expiry.After(time.Now().Add(30*time.Minute)))
	assert.Equal(t, []string{"openid", "tasks"}, grant.Scopes)
	assert.Equal(t, httpclient.Registration{ClientID: "client"}, grant.Client)
	assert.Equal(t, metadata, grant.Server)

	// A code which is refused, and one without its verifier, are bad
	// parameters
	code.Code = "other"
	_, err = httpclient.ExchangeCode(ctx, metadata, client, code)
	assert.ErrorIs(t, err, goauth.ErrBadParameter)
	code.Code, code.CodeVerifier = "code", ""
	_, err = httpclient.ExchangeCode(ctx, metadata, client, code)
	assert.ErrorIs(t, err, goauth.ErrBadParameter)
}
