// Copyright 2026 David Thorpe
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package certmanager

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
	tokens *auth.TokenSource
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func newAuthTransport(parent http.RoundTripper, ctx server.Cmd, authClient *auth.Client) http.RoundTripper {
	if parent == nil {
		parent = http.DefaultTransport
	}
	return &authTransport{
		RoundTripper: parent,
		tokens:       authClient.NewTokenSource(NewCmdTokenStore(ctx), ""),
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
