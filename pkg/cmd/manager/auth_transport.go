package manager

import (
	"fmt"
	"net/http"
	"strings"

	// Packages
	auth "github.com/djthorpe/go-auth/pkg/httpclient/auth"
	server "github.com/mutablelogic/go-server"
	oauth2 "golang.org/x/oauth2"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type authTransport struct {
	http.RoundTripper
	tokens *TokenSource
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func newAuthTransport(parent http.RoundTripper, ctx server.Cmd, endpoint string, authClient *auth.Client) http.RoundTripper {
	if parent == nil {
		parent = http.DefaultTransport
	}
	return &authTransport{
		RoundTripper: parent,
		tokens:       NewTokenSource(NewCmdTokenStore(ctx), endpoint, authClient),
	}
}

func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil {
		return t.RoundTripper.RoundTrip(req)
	}

	token, err := t.tokens.Token()
	if err != nil {
		return nil, err
	}
	reqWithToken, err := cloneRequestWithAuthorization(req, token, false)
	if err != nil {
		return nil, err
	}
	resp, err := t.RoundTripper.RoundTrip(reqWithToken)
	if err != nil || resp == nil || resp.StatusCode != http.StatusUnauthorized {
		return resp, err
	}

	refreshed, refreshErr := t.tokens.Refresh()
	if refreshErr != nil || refreshed == nil || strings.TrimSpace(refreshed.AccessToken) == "" || strings.TrimSpace(refreshed.AccessToken) == strings.TrimSpace(token.AccessToken) {
		return resp, nil
	}
	retryReq, err := cloneRequestWithAuthorization(req, refreshed, true)
	if err != nil {
		return resp, nil
	}
	_ = resp.Body.Close()
	return t.RoundTripper.RoundTrip(retryReq)
}

func cloneRequestWithAuthorization(req *http.Request, token *oauth2.Token, replayBody bool) (*http.Request, error) {
	if req == nil {
		return nil, fmt.Errorf("request is required")
	}
	clone := req.Clone(req.Context())
	if replayBody && req.Body != nil && req.Body != http.NoBody {
		if req.GetBody == nil {
			return nil, fmt.Errorf("request body cannot be replayed")
		}
		body, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		clone.Body = body
	}
	if token != nil && strings.TrimSpace(token.AccessToken) != "" {
		token.SetAuthHeader(clone)
	}
	return clone, nil
}
