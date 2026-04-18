package httphandler

import (
	"net/url"
	"testing"

	// Packages
	oidc "github.com/mutablelogic/go-auth/auth/oidc"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestAuthRequestValidateAcceptsRedirectURI(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	values := url.Values{
		"provider":              {"local"},
		"redirect_uri":          {"http://127.0.0.1:8085/callback"},
		"response_type":         {oidc.ResponseTypeCode},
		"scope":                 {"openid email profile"},
		"state":                 {"test-state"},
		"code_challenge":        {"challenge-value"},
		"code_challenge_method": {oidc.CodeChallengeMethodS256},
	}

	var req AuthRequest
	require.NoError(httprequest.Query(values, &req))
	require.NoError(req.Validate())
	assert.Equal("http://127.0.0.1:8085/callback", req.RedirectURL)
	assert.Equal(oidc.CodeChallengeMethodS256, req.CodeChallengeMethod)
	assert.Equal([]string{"openid email profile"}, req.Scopes)
	assert.Equal("local", req.Provider)
	assert.Equal(oidc.CodeChallengeMethodS256, req.CodeChallengeMethod)
}

func TestAuthRequestValidateRequiresRedirectURI(t *testing.T) {
	assert := assert.New(t)

	req := AuthRequest{}
	err := req.Validate()
	assert.Error(err)
	assert.Contains(err.Error(), "redirect_uri is required")
}
