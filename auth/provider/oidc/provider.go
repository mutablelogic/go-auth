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

// Package oidc is a provider which is an OpenID Connect issuer, such as
// Google, Microsoft or Keycloak, which is signed in with at its own pages,
// and whose ID tokens are checked against its keys.
package oidc

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"

	// Packages
	gooidc "github.com/coreos/go-oidc/v3/oidc"
	client "github.com/mutablelogic/go-client"
	provider "github.com/mutablelogic/go-auth/auth/provider"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	oauth2 "golang.org/x/oauth2"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// Provider is an OpenID Connect issuer, which is discovered when it's first
// used, so the server starts without it
type Provider struct {
	meta         schema.ProviderMeta
	issuer       string
	clientID     string
	clientSecret string
	scopes       []string
	groups       string
	clientOpts   []client.ClientOpt
	client       *client.Client

	mu       sync.Mutex
	provider *gooidc.Provider
}

// Opt is an option of a provider
type Opt func(*Provider) error

var _ provider.RedirectProvider = (*Provider)(nil)

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

const (
	// GoogleIssuer is Google's issuer
	GoogleIssuer = "https://accounts.google.com"
)

// claims which are an identity's own fields, or about the token, rather
// than the person, which aren't its other claims
var standardClaims = map[string]bool{
	"iss": true, "sub": true, "aud": true, "exp": true, "iat": true, "nbf": true, "jti": true,
	"azp": true, "at_hash": true, "c_hash": true, "nonce": true, "auth_time": true, "acr": true, "amr": true, "sid": true,
	"email": true, "email_verified": true, "name": true,
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// New returns a provider, with a name, which is in its paths, and a label,
// to show, of the issuer, with the client's ID and secret, which it's
// registered with at the issuer. It asks for openid, email and profile.
func New(name, label, issuer, clientID, clientSecret string, opts ...Opt) (*Provider, error) {
	switch {
	case name == "":
		return nil, httpresponse.ErrBadRequest.With("An OIDC provider needs a name")
	case issuer == "":
		return nil, httpresponse.ErrBadRequest.Withf("%s needs an issuer", name)
	case clientID == "":
		return nil, httpresponse.ErrBadRequest.Withf("%s needs a client ID", name)
	}
	self := &Provider{
		meta:         schema.ProviderMeta{Name: name, Label: label, Kind: schema.ProviderKindRedirect},
		issuer:       strings.TrimSuffix(issuer, "/"),
		clientID:     clientID,
		clientSecret: clientSecret,
		scopes:       []string{gooidc.ScopeOpenID, "email", "profile"},
	}
	if self.meta.Label == "" {
		self.meta.Label = name
	}
	for _, opt := range opts {
		if err := opt(self); err != nil {
			return nil, err
		}
	}

	// The client of the issuer, whose options, such as for tracing and
	// timeouts, are for discovery, its keys, and exchanges
	c, err := client.New(append([]client.ClientOpt{client.OptEndpoint(self.issuer)}, self.clientOpts...)...)
	if err != nil {
		return nil, err
	}
	self.client, self.clientOpts = c, nil
	return self, nil
}

// NewGoogle returns a provider of Google, named google, with the client's
// ID and secret, from the Google Cloud Console
func NewGoogle(clientID, clientSecret string, opts ...Opt) (*Provider, error) {
	return New("google", "Google", GoogleIssuer, clientID, clientSecret, opts...)
}

///////////////////////////////////////////////////////////////////////////////
// OPTIONS

// WithScopes asks for scopes, other than openid, email and profile
func WithScopes(scopes ...string) Opt {
	return func(p *Provider) error {
		for _, scope := range scopes {
			if scope = strings.TrimSpace(scope); scope != "" {
				p.scopes = append(p.scopes, scope)
			}
		}
		return nil
	}
}

// WithGroupsClaim takes the identity's groups from the claim, such as
// groups, which some issuers, such as Keycloak, make
func WithGroupsClaim(claim string) Opt {
	return func(p *Provider) error {
		p.groups = claim
		return nil
	}
}

// WithClient sets options of the client which discovers the issuer, gets
// its keys, and exchanges codes, such as client.OptTracer, or OptTimeout
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

// AuthCodeURL returns the URL of the issuer's sign-in page, which redirects
// to the redirect URL with a code, and the state, with the S256 challenge of
// the verifier
func (p *Provider) AuthCodeURL(ctx context.Context, redirectURL, state, verifier string) (string, error) {
	if redirectURL == "" || state == "" || verifier == "" {
		return "", httpresponse.ErrBadRequest.With("A redirect URL, state and verifier are needed")
	}
	discovered, err := p.discover(ctx)
	if err != nil {
		return "", err
	}
	return p.config(discovered, redirectURL).AuthCodeURL(state, oauth2.S256ChallengeOption(verifier)), nil
}

// Exchange exchanges the code, with its verifier, for tokens, and returns
// the identity of the ID token, which is checked against the issuer's keys,
// and is for this client
func (p *Provider) Exchange(ctx context.Context, credential schema.Credential) (*schema.Identity, error) {
	if credential.Code == "" || credential.CodeVerifier == "" || credential.RedirectURL == "" {
		return nil, httpresponse.ErrBadRequest.With("A code, its verifier and the redirect URL are needed")
	}
	discovered, err := p.discover(ctx)
	if err != nil {
		return nil, err
	}

	// Exchange the code
	ctx = gooidc.ClientContext(ctx, p.client.Client)
	token, err := p.config(discovered, credential.RedirectURL).Exchange(ctx, credential.Code, oauth2.VerifierOption(credential.CodeVerifier))
	if err != nil {
		return nil, exchangeErr(p.meta.Name, err)
	}
	raw, _ := token.Extra("id_token").(string)
	if raw == "" {
		return nil, httpresponse.ErrGatewayError.Withf("%s returned no ID token", p.meta.Name)
	}

	// Check the ID token, which is for this client, and its claims
	idToken, err := discovered.Verifier(&gooidc.Config{ClientID: p.clientID}).Verify(ctx, raw)
	if err != nil {
		return nil, httpresponse.ErrNotAuthorized.Withf("%s's ID token isn't valid: %v", p.meta.Name, err)
	}
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return nil, httpresponse.ErrGatewayError.Withf("%s's ID token's claims: %v", p.meta.Name, err)
	}
	return p.identity(idToken.Issuer, idToken.Subject, claims), nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// discover returns the issuer's configuration, which is fetched once it's
// first needed, and again when it couldn't be
func (p *Provider) discover(ctx context.Context) (*gooidc.Provider, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.provider != nil {
		return p.provider, nil
	}
	discovered, err := gooidc.NewProvider(gooidc.ClientContext(ctx, p.client.Client), p.issuer)
	if err != nil {
		return nil, httpresponse.ErrGatewayError.Withf("%s can't be discovered: %v", p.meta.Name, err)
	}
	p.provider = discovered
	return discovered, nil
}

// config returns the OAuth2 configuration of the client, at the issuer,
// which redirects to the URL
func (p *Provider) config(discovered *gooidc.Provider, redirectURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     p.clientID,
		ClientSecret: p.clientSecret,
		Endpoint:     discovered.Endpoint(),
		RedirectURL:  redirectURL,
		Scopes:       p.scopes,
	}
}

// identity returns the identity of the ID token's claims
func (p *Provider) identity(issuer, subject string, claims map[string]any) *schema.Identity {
	identity := &schema.Identity{
		Provider: p.meta.Name,
		Issuer:   issuer,
		Subject:  subject,
		Email:    stringClaim(claims["email"]),
		Name:     stringClaim(claims["name"]),
	}
	switch verified := claims["email_verified"].(type) {
	case bool:
		identity.EmailVerified = verified
	case string:
		identity.EmailVerified = strings.EqualFold(verified, "true")
	}
	if p.groups != "" {
		if values, ok := claims[p.groups].([]any); ok {
			for _, value := range values {
				if group := stringClaim(value); group != "" {
					identity.Groups = append(identity.Groups, group)
				}
			}
		}
	}
	for key, value := range claims {
		if !standardClaims[key] && key != p.groups {
			if identity.Claims == nil {
				identity.Claims = make(map[string]any)
			}
			identity.Claims[key] = value
		}
	}
	return identity
}

// stringClaim returns a claim which is a string, or empty
func stringClaim(value any) string {
	s, _ := value.(string)
	return s
}

// exchangeErr returns the error of an exchange: not authorized when the
// issuer refused the code, such as when it's been used, or its verifier
// isn't right, or else a gateway error
func exchangeErr(name string, err error) error {
	var retrieve *oauth2.RetrieveError
	if errors.As(err, &retrieve) && retrieve.Response != nil && retrieve.Response.StatusCode < http.StatusInternalServerError {
		return httpresponse.ErrNotAuthorized.Withf("%s refused the code: %s", name, retrieveReason(retrieve))
	}
	return httpresponse.ErrGatewayError.Withf("%s: %v", name, err)
}

// retrieveReason is the issuer's reason for refusing a code
func retrieveReason(err *oauth2.RetrieveError) string {
	if err.ErrorDescription != "" {
		return err.ErrorDescription
	} else if err.ErrorCode != "" {
		return err.ErrorCode
	}
	return http.StatusText(err.Response.StatusCode)
}
