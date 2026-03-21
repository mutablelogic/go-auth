package main

import (
	"strings"
	"testing"

	// Packages
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
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
