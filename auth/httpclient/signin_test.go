package httpclient_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	// Packages
	goauth "github.com/mutablelogic/go-auth"
	httpclient "github.com/mutablelogic/go-auth/auth/httpclient"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
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
