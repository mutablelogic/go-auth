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

package httpclient

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	// Packages
	goauth "github.com/mutablelogic/go-auth"
	oauth2 "golang.org/x/oauth2"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// Grant is what a resource was authorized with: its authorization server,
// the client, the redirect URI, the resource and scopes, and the token,
// which is refreshed with them, so it's what's kept
type Grant struct {
	Server      ServerMetadata `json:"server"`
	Client      Registration   `json:"client"`
	RedirectURI string         `json:"redirect_uri"`
	Resource    string         `json:"resource,omitempty"`
	Scopes      []string       `json:"scopes,omitempty"`
	Token       *oauth2.Token  `json:"token,omitempty"`
}

// Authorization is an authorization which is waited for: the URL a person
// authorizes it at, its state, which its callback is matched with, and its
// PKCE verifier, which its code is exchanged with
type Authorization struct {
	Grant
	URL      string `json:"url"`
	State    string `json:"-"`
	Verifier string `json:"-"`
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// Authorize starts the authorization of the resource, whose metadata is
// discovered, by its first authorization server, which needs to support
// PKCE's S256, for the client, which is registered, with the redirect URI,
// and the scopes, or else those the resource says it supports, and returns
// the URL a person authorizes it at. Returns ErrNotImplemented when the
// server doesn't support S256, and ErrBadParameter when the redirect URI
// isn't an http, or https, URL.
func (c *Client) Authorize(metadata *Metadata, client Registration, redirectURI string, scopes ...string) (*Authorization, error) {
	if metadata == nil || len(metadata.AuthorizationServers) == 0 {
		return nil, goauth.ErrBadParameter.With("no authorization server")
	} else if u, err := url.Parse(redirectURI); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, goauth.ErrBadParameter.Withf("redirect URI %q isn't an http, or https, URL", redirectURI)
	} else if client.ClientID == "" {
		return nil, goauth.ErrBadParameter.With("no client")
	}
	server := metadata.AuthorizationServers[0]
	if !server.SupportsS256() {
		return nil, goauth.ErrNotImplemented.Withf("authorization server %q doesn't support PKCE's S256", server.Issuer)
	}
	resource := metadata.Resource.Resource
	if resource == "" {
		resource = c.endpoint
	}
	if len(scopes) == 0 {
		scopes = metadata.Resource.ScopesSupported
	}
	a := &Authorization{
		Grant:    Grant{Server: server, Client: client, RedirectURI: redirectURI, Resource: resource, Scopes: scopes},
		State:    oauth2.GenerateVerifier(),
		Verifier: oauth2.GenerateVerifier(),
	}
	a.URL = server.Config(client, redirectURI, scopes...).AuthCodeURL(a.State, oauth2.S256ChallengeOption(a.Verifier), oauth2.SetAuthURLParam("resource", resource))
	return a, nil
}

// Exchange completes the authorization, with its callback's query: the
// state, which must be the authorization's, and the code, which is
// exchanged, with the verifier, for a token, or the error the
// authorization server said. Returns the grant, with the token, or
// ErrBadParameter, when it wasn't authorized, or the code couldn't be
// exchanged.
func (c *Client) Exchange(ctx context.Context, a *Authorization, query url.Values) (*Grant, error) {
	if a == nil {
		return nil, goauth.ErrBadParameter.With("no authorization")
	} else if subtle.ConstantTimeCompare([]byte(query.Get("state")), []byte(a.State)) != 1 {
		return nil, goauth.ErrBadParameter.With("the state isn't the authorization's")
	} else if reason := query.Get("error"); reason != "" {
		if description := query.Get("error_description"); description != "" {
			reason = description
		}
		return nil, goauth.ErrBadParameter.Withf("it wasn't authorized: %s", reason)
	} else if query.Get("code") == "" {
		return nil, goauth.ErrBadParameter.With("missing code")
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, c.metadata.Client)
	token, err := a.Server.Config(a.Client, a.RedirectURI, a.Scopes...).Exchange(ctx, query.Get("code"), oauth2.VerifierOption(a.Verifier), oauth2.SetAuthURLParam("resource", a.Resource))
	if err != nil {
		return nil, goauth.ErrBadParameter.Withf("the code couldn't be exchanged: %v", err)
	}
	grant := a.Grant
	grant.Token = token
	return &grant, nil
}

// TokenSource returns a source of the grant's token, which is refreshed,
// with its refresh token, client and resource indicator, when it's
// expired, with the client's options, and fn, when it isn't nil, is called
// with a new token, so it's kept
func (c *Client) TokenSource(ctx context.Context, grant *Grant, fn func(*oauth2.Token)) oauth2.TokenSource {
	return &refresher{ctx: ctx, http: c.metadata.Client, grant: *grant, token: grant.Token, fn: fn}
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE TYPES

// refresher is a source of a grant's token, which refreshes it, as oauth2's
// does, with the resource indicator, which oauth2's doesn't send
type refresher struct {
	mu    sync.Mutex
	ctx   context.Context
	http  *http.Client
	grant Grant
	token *oauth2.Token
	fn    func(*oauth2.Token)
}

// tokenResponse is a token endpoint's response, or its error
type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresIn        int64  `json:"expires_in"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// Token returns the token, while it's valid, or else refreshes it
func (r *refresher) Token() (*oauth2.Token, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.token.Valid() {
		return r.token, nil
	} else if r.token == nil || r.token.RefreshToken == "" {
		return nil, goauth.ErrBadParameter.With("the token has expired, and can't be refreshed")
	}

	// The refresh, with the client, which is authenticated with HTTP Basic,
	// with a secret, as RFC 6749 has it, or else by its ID
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {r.token.RefreshToken}}
	if r.grant.Resource != "" {
		form.Set("resource", r.grant.Resource)
	}
	if r.grant.Client.ClientSecret == "" {
		form.Set("client_id", r.grant.Client.ClientID)
	}
	req, err := http.NewRequestWithContext(r.ctx, http.MethodPost, r.grant.Server.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if r.grant.Client.ClientSecret != "" {
		req.SetBasicAuth(url.QueryEscape(r.grant.Client.ClientID), url.QueryEscape(r.grant.Client.ClientSecret))
	}
	resp, err := r.http.Do(req)
	if err != nil {
		return nil, goauth.ErrServiceUnavailable.Withf("refresh: %v", err)
	}
	defer resp.Body.Close()
	var body tokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil && resp.StatusCode == http.StatusOK {
		return nil, goauth.ErrServiceUnavailable.Withf("refresh: %v", err)
	}
	if resp.StatusCode != http.StatusOK || body.Error != "" || body.AccessToken == "" {
		reason := body.ErrorDescription
		if reason == "" {
			reason = body.Error
		}
		if reason == "" {
			reason = resp.Status
		}
		return nil, goauth.ErrBadParameter.Withf("the token couldn't be refreshed: %s", reason)
	}

	// The new token, which keeps the refresh token, when there's no other
	token := &oauth2.Token{AccessToken: body.AccessToken, TokenType: body.TokenType, RefreshToken: body.RefreshToken}
	if token.RefreshToken == "" {
		token.RefreshToken = r.token.RefreshToken
	}
	if body.ExpiresIn > 0 {
		token.Expiry = time.Now().Add(time.Duration(body.ExpiresIn) * time.Second)
	}
	r.token = token
	if r.fn != nil {
		r.fn(token)
	}
	return token, nil
}
