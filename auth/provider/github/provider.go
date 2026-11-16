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
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	// Packages
	provider "github.com/mutablelogic/go-auth/auth/provider"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	credential "github.com/mutablelogic/go-auth/credential"
	client "github.com/mutablelogic/go-client"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	oauth2 "golang.org/x/oauth2"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// Provider is GitHub, whose OAuth app is a credential
type Provider struct {
	meta        schema.ProviderMeta
	credentials credential.CredentialProvider
	key         string
	web, api    string
	orgs        bool
	clientOpts  []client.ClientOpt
	client      *client.Client
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
	// perPage is the most of a list the API returns on a page
	perPage = 100

	// DefaultURL and DefaultAPIURL are GitHub's, rather than GitHub
	// Enterprise's
	DefaultURL    = "https://github.com"
	DefaultAPIURL = "https://api.github.com"
)

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// New returns GitHub, named github, whose OAuth app is the credential at
// the key: an OAuthClient, with its client ID and secret. It asks to read
// the user, and their email addresses.
func New(credentials credential.CredentialProvider, key string, opts ...Opt) (*Provider, error) {
	if credentials == nil || key == "" {
		return nil, httpresponse.ErrBadRequest.With("GitHub needs the credential of its OAuth app")
	}
	self := &Provider{
		meta:        schema.ProviderMeta{Name: "github", Label: "GitHub", Kind: schema.ProviderKindRedirect},
		credentials: credentials,
		key:         key,
		web:         DefaultURL,
		api:         DefaultAPIURL,
	}
	for _, opt := range opts {
		if err := opt(self); err != nil {
			return nil, err
		}
	}

	// The client of the API, whose options, such as for tracing and
	// timeouts, are for exchanges too
	c, err := client.New(append([]client.ClientOpt{client.OptEndpoint(self.api)}, self.clientOpts...)...)
	if err != nil {
		return nil, err
	}
	self.client, self.clientOpts = c, nil
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

// WithClient sets options of the client which exchanges codes, and calls
// the API, such as client.OptTracer, or OptTimeout
func WithClient(opts ...client.ClientOpt) Opt {
	return func(p *Provider) error {
		p.clientOpts = append(p.clientOpts, opts...)
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
func (p *Provider) AuthCodeURL(ctx context.Context, redirectURL, state, verifier string) (string, error) {
	if redirectURL == "" || state == "" || verifier == "" {
		return "", httpresponse.ErrBadRequest.With("A redirect URL, state and verifier are needed")
	}
	app, err := provider.Client(ctx, p.credentials, p.key)
	if err != nil {
		return "", err
	}
	return p.config(app, redirectURL).AuthCodeURL(state, oauth2.S256ChallengeOption(verifier)), nil
}

// Exchange exchanges the code, with its verifier, for a token, and returns
// the identity of the user it's for: their ID, which doesn't change, their
// name, or login, their primary email address, and their organisations,
// when they're asked for
func (p *Provider) Exchange(ctx context.Context, credential schema.Credential) (*schema.Identity, error) {
	if credential.Code == "" || credential.CodeVerifier == "" || credential.RedirectURL == "" {
		return nil, httpresponse.ErrBadRequest.With("A code, its verifier and the redirect URL are needed")
	}
	app, err := provider.Client(ctx, p.credentials, p.key)
	if err != nil {
		return nil, err
	}
	exchange := context.WithValue(ctx, oauth2.HTTPClient, p.client.Client)
	token, err := p.config(app, credential.RedirectURL).Exchange(exchange, credential.Code, oauth2.VerifierOption(credential.CodeVerifier))
	if err != nil {
		return nil, exchangeErr(err)
	}
	bearer := client.Token{Scheme: client.Bearer, Value: token.AccessToken}

	// The user, their email addresses, and organisations
	var u user
	if err := p.get(ctx, bearer, &u, nil, "user"); err != nil {
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
	emails, err := getAll[email](ctx, p, bearer, "user", "emails")
	if err != nil {
		return nil, err
	}
	for _, e := range emails {
		if e.Primary {
			identity.Email, identity.EmailVerified = e.Email, e.Verified
		}
	}
	if p.orgs {
		orgs, err := getAll[org](ctx, p, bearer, "user", "orgs")
		if err != nil {
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
func (p *Provider) config(app *schema.OAuthClient, redirectURL string) *oauth2.Config {
	scopes := []string{"read:user", "user:email"}
	if p.orgs {
		scopes = append(scopes, "read:org")
	}
	return &oauth2.Config{
		ClientID:     app.ClientID,
		ClientSecret: app.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  p.web + "/login/oauth/authorize",
			TokenURL: p.web + "/login/oauth/access_token",
		},
		RedirectURL: redirectURL,
		Scopes:      scopes,
	}
}

// getAll returns every page of a list, which the API pages, with the most
// on each, until a page has fewer
func getAll[T any](ctx context.Context, p *Provider, token client.Token, path ...string) ([]T, error) {
	var result []T
	for page := 1; ; page++ {
		var items []T
		query := url.Values{"per_page": {strconv.Itoa(perPage)}, "page": {strconv.Itoa(page)}}
		if err := p.get(ctx, token, &items, query, path...); err != nil {
			return nil, err
		}
		result = append(result, items...)
		if len(items) < perPage {
			return result, nil
		}
	}
}

// get calls the API, at the path's segments, with the token, and decodes
// its response
func (p *Provider) get(ctx context.Context, token client.Token, v any, query url.Values, path ...string) error {
	segments := make([]any, len(path))
	for i, segment := range path {
		segments[i] = segment
	}
	if err := p.client.DoWithContext(ctx, client.NewRequest(), v,
		client.OptPath(segments...), client.OptQuery(query), client.OptToken(token), client.OptReqHeader("Accept", "application/vnd.github+json"),
	); err != nil {
		return httpresponse.ErrGatewayError.Withf("GitHub's /%s: %v", strings.Join(path, "/"), err)
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
