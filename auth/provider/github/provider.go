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

// Package github is a provider of GitHub, or GitHub Enterprise, which is
// signed in with at GitHub, as an OAuth app, which isn't OpenID Connect, so
// the identity is the user GitHub's API says the token is for.
package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	// Packages
	provider "github.com/mutablelogic/go-auth/auth/provider"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	oauth2 "golang.org/x/oauth2"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// Provider is GitHub, with an OAuth app's client ID and secret
type Provider struct {
	meta         schema.ProviderMeta
	clientID     string
	clientSecret string
	web, api     string
	orgs         bool
	client       *http.Client
}

// Opt is an option of a provider
type Opt func(*Provider) error

var _ provider.RedirectProvider = (*Provider)(nil)

// user is GitHub's user, and email
type user struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
	HTMLURL   string `json:"html_url"`
}

type email struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

type org struct {
	Login string `json:"login"`
}

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

const (
	// DefaultURL and DefaultAPIURL are GitHub's, rather than GitHub
	// Enterprise's
	DefaultURL    = "https://github.com"
	DefaultAPIURL = "https://api.github.com"
)

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// New returns GitHub, named github, with an OAuth app's client ID and
// secret, which asks to read the user, and their email addresses
func New(clientID, clientSecret string, opts ...Opt) (*Provider, error) {
	if clientID == "" || clientSecret == "" {
		return nil, httpresponse.ErrBadRequest.With("GitHub needs a client ID and secret")
	}
	self := &Provider{
		meta:         schema.ProviderMeta{Name: "github", Label: "GitHub", Kind: schema.ProviderKindRedirect},
		clientID:     clientID,
		clientSecret: clientSecret,
		web:          DefaultURL,
		api:          DefaultAPIURL,
		client:       http.DefaultClient,
	}
	for _, opt := range opts {
		if err := opt(self); err != nil {
			return nil, err
		}
	}
	return self, nil
}

///////////////////////////////////////////////////////////////////////////////
// OPTIONS

// WithURL is GitHub Enterprise, at its URL, and its API's
func WithURL(web, api string) Opt {
	return func(p *Provider) error {
		if web == "" || api == "" {
			return httpresponse.ErrBadRequest.With("GitHub Enterprise needs its URL and its API's")
		}
		p.web, p.api = strings.TrimSuffix(web, "/"), strings.TrimSuffix(api, "/")
		return nil
	}
}

// WithOrganizations asks to read the user's organisations, which are the
// identity's groups
func WithOrganizations() Opt {
	return func(p *Provider) error {
		p.orgs = true
		return nil
	}
}

// WithHTTPClient exchanges codes, and calls the API, with the client
func WithHTTPClient(client *http.Client) Opt {
	return func(p *Provider) error {
		if client == nil {
			return httpresponse.ErrBadRequest.With("No HTTP client")
		}
		p.client = client
		return nil
	}
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// Meta describes the provider
func (p *Provider) Meta() schema.ProviderMeta {
	return p.meta
}

// AuthCodeURL returns the URL of GitHub's sign-in page, which redirects to
// the redirect URL with a code, and the state, with the S256 challenge of
// the verifier
func (p *Provider) AuthCodeURL(_ context.Context, redirectURL, state, verifier string) (string, error) {
	if redirectURL == "" || state == "" || verifier == "" {
		return "", httpresponse.ErrBadRequest.With("A redirect URL, state and verifier are needed")
	}
	return p.config(redirectURL).AuthCodeURL(state, oauth2.S256ChallengeOption(verifier)), nil
}

// Exchange exchanges the code, with its verifier, for a token, and returns
// the identity of the user it's for: their ID, which doesn't change, their
// name, or login, their primary email address, and their organisations,
// when they're asked for
func (p *Provider) Exchange(ctx context.Context, credential schema.Credential) (*schema.Identity, error) {
	if credential.Code == "" || credential.CodeVerifier == "" || credential.RedirectURL == "" {
		return nil, httpresponse.ErrBadRequest.With("A code, its verifier and the redirect URL are needed")
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, p.client)
	config := p.config(credential.RedirectURL)
	token, err := config.Exchange(ctx, credential.Code, oauth2.VerifierOption(credential.CodeVerifier))
	if err != nil {
		return nil, exchangeErr(err)
	}
	client := config.Client(ctx, token)

	// The user, their email addresses, and organisations
	var u user
	if err := p.get(ctx, client, "/user", &u); err != nil {
		return nil, err
	} else if u.ID == 0 {
		return nil, httpresponse.ErrGatewayError.With("GitHub returned no user")
	}
	identity := &schema.Identity{
		Provider: p.meta.Name,
		Issuer:   p.web,
		Subject:  strconv.FormatInt(u.ID, 10),
		Name:     u.Name,
		Email:    u.Email,
		Claims:   map[string]any{"login": u.Login},
	}
	if identity.Name == "" {
		identity.Name = u.Login
	}
	if u.AvatarURL != "" {
		identity.Claims["avatar_url"] = u.AvatarURL
	}
	if u.HTMLURL != "" {
		identity.Claims["html_url"] = u.HTMLURL
	}
	var emails []email
	if err := p.get(ctx, client, "/user/emails", &emails); err != nil {
		return nil, err
	}
	for _, e := range emails {
		if e.Primary {
			identity.Email, identity.EmailVerified = e.Email, e.Verified
		}
	}
	if p.orgs {
		var orgs []org
		if err := p.get(ctx, client, "/user/orgs", &orgs); err != nil {
			return nil, err
		}
		for _, o := range orgs {
			identity.Groups = append(identity.Groups, o.Login)
		}
	}
	return identity, nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// config returns the OAuth2 configuration of the app, which redirects to
// the URL
func (p *Provider) config(redirectURL string) *oauth2.Config {
	scopes := []string{"read:user", "user:email"}
	if p.orgs {
		scopes = append(scopes, "read:org")
	}
	return &oauth2.Config{
		ClientID:     p.clientID,
		ClientSecret: p.clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  p.web + "/login/oauth/authorize",
			TokenURL: p.web + "/login/oauth/access_token",
		},
		RedirectURL: redirectURL,
		Scopes:      scopes,
	}
}

// get calls the API, with the token's client, and decodes its response
func (p *Provider) get(ctx context.Context, client *http.Client, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.api+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	response, err := client.Do(req)
	if err != nil {
		return httpresponse.ErrGatewayError.Withf("GitHub: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return httpresponse.ErrGatewayError.Withf("GitHub's %s: %s", path, response.Status)
	}
	if err := json.NewDecoder(response.Body).Decode(v); err != nil {
		return httpresponse.ErrGatewayError.Withf("GitHub's %s: %v", path, err)
	}
	return nil
}

// exchangeErr returns the error of an exchange: not authorized when GitHub
// refused the code, or else a gateway error. GitHub refuses a code with 200,
// and an error, which the client returns as a RetrieveError too.
func exchangeErr(err error) error {
	var retrieve *oauth2.RetrieveError
	if errors.As(err, &retrieve) && (retrieve.ErrorCode != "" || (retrieve.Response != nil && retrieve.Response.StatusCode < http.StatusInternalServerError)) {
		reason := retrieve.ErrorDescription
		if reason == "" {
			reason = fmt.Sprint(retrieve.ErrorCode)
		}
		return httpresponse.ErrNotAuthorized.Withf("GitHub refused the code: %s", reason)
	}
	return httpresponse.ErrGatewayError.Withf("GitHub: %v", err)
}
