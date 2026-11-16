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

package httphandler

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	// Packages
	httpclient "github.com/mutablelogic/go-auth/auth/httpclient"
	provider "github.com/mutablelogic/go-auth/auth/provider"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	security "github.com/mutablelogic/go-auth/auth/security"
	store "github.com/mutablelogic/go-auth/auth/store"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	httprouter "github.com/mutablelogic/go-server/pkg/httprouter"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
	opts "github.com/mutablelogic/go-server/pkg/openapi"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// oauthClient is a registered client, which is its ID, sealed, so it isn't
// kept: a public client, with PKCE, and its redirect URIs
type oauthClient struct {
	Name      string   `json:"n,omitempty"`
	Redirects []string `json:"r"`
	Issued    int64    `json:"i"`
}

// oauthCode is an authorization code, sealed, which is exchanged once,
// before it expires, by its client, with the verifier of its challenge,
// for a session of the user, with the scopes, which ends with theirs
type oauthCode struct {
	ID        string      `json:"id"`
	Client    string      `json:"c"`
	Redirect  string      `json:"r"`
	Given     bool        `json:"g,omitempty"`
	Challenge string      `json:"x"`
	Resource  string      `json:"res,omitempty"`
	User      schema.User `json:"u"`
	Provider  string      `json:"p"`
	Scopes    []string    `json:"s,omitempty"`
	Ends      int64       `json:"se"`
	Expires   int64       `json:"e"`
}

// consumed are the codes which have been exchanged, by ID, until they
// expire, by this server, when the sessions don't consume them
type consumed struct {
	sync.Mutex
	codes map[string]int64
}

// registerRequest is a client's registration, as RFC 7591 has it
type registerRequest struct {
	ClientName              string   `json:"client_name,omitempty" help:"Name of the client, to show"`
	RedirectURIs            []string `json:"redirect_uris" help:"Where the client is redirected back to, with a code" required:""`
	GrantTypes              []string `json:"grant_types,omitempty" help:"Grants the client uses, which are authorization_code"`
	ResponseTypes           []string `json:"response_types,omitempty" help:"Responses the client uses, which are code"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty" help:"How the client authenticates, which is none, as it's public"`
	Scope                   string   `json:"scope,omitempty" help:"Scopes the client asks for, separated by spaces"`
}

// registerResponse is a registered client
type registerResponse struct {
	ClientID                string   `json:"client_id" help:"ID of the client, which is sent with its requests"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at" help:"When the ID was issued, in seconds since the epoch"`
	ClientName              string   `json:"client_name,omitempty" help:"Name of the client"`
	RedirectURIs            []string `json:"redirect_uris" help:"Where the client is redirected back to"`
	GrantTypes              []string `json:"grant_types" help:"Grants the client uses"`
	ResponseTypes           []string `json:"response_types" help:"Responses the client uses"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method" help:"How the client authenticates, which is none"`
}

// authorizeQuery is the query of an authorization request
type authorizeQuery struct {
	ResponseType        string `json:"response_type" help:"The response, which is code"`
	ClientID            string `json:"client_id" help:"ID of the client, from its registration"`
	RedirectURI         string `json:"redirect_uri,omitempty" help:"One of the client's redirect URIs, which a loopback one's port can differ from"`
	State               string `json:"state,omitempty" help:"State, which is returned with the code"`
	Scope               string `json:"scope,omitempty" help:"Scopes to ask for, separated by spaces. Without them, they're the session's."`
	Resource            string `json:"resource,omitempty" help:"Resource the token is for, which is this server's API"`
	CodeChallenge       string `json:"code_challenge" help:"PKCE challenge"`
	CodeChallengeMethod string `json:"code_challenge_method" help:"PKCE challenge method, which is S256"`
}

// tokenRequest is a request of the token endpoint
type tokenRequest struct {
	GrantType    string `json:"grant_type" help:"The grant, which is authorization_code" required:""`
	Code         string `json:"code,omitempty" help:"Authorization code"`
	RedirectURI  string `json:"redirect_uri,omitempty" help:"Redirect URI the code was for"`
	ClientID     string `json:"client_id,omitempty" help:"ID of the client the code was for"`
	CodeVerifier string `json:"code_verifier,omitempty" help:"PKCE verifier of the code's challenge"`
	Resource     string `json:"resource,omitempty" help:"Resource the token is for"`
}

// tokenResponse is an access token, which is a session's
type tokenResponse struct {
	AccessToken string `json:"access_token" help:"Token of the session, which is sent as a bearer token"`
	TokenType   string `json:"token_type" help:"Bearer"`
	ExpiresIn   int64  `json:"expires_in" help:"Seconds until the session ends"`
	Scope       string `json:"scope" help:"The session's scopes, separated by spaces, which can be fewer than were asked for, or none"`
}

// oauthError is an OAuth error, as its endpoints return them
type oauthError struct {
	Error       string `json:"error" help:"Error, such as invalid_grant"`
	Description string `json:"error_description,omitempty" help:"Why"`
}

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

const (
	// The OpenAPI tag of the OAuth server's operations
	tagOAuth = "OAuth"

	// The well-known paths of the metadata, as RFC 8414 and 9728 have them
	pathServerMetadata   = "/.well-known/oauth-authorization-server"
	pathResourceMetadata = "/.well-known/oauth-protected-resource"

	// How long a code can be exchanged for
	codeTTL = time.Minute

	// The most a registration, or a token request, is read of
	maxRegistration = 16 << 10
	maxForm         = 64 << 10

	// The longest a client's ID is, sealed, so it fits in a token request,
	// with a code
	maxClientID = 4 << 10
)

///////////////////////////////////////////////////////////////////////////////
// OPTIONS

// WithOAuth makes the server an OAuth authorization server, as MCP clients
// expect, which issues its sessions to clients: it publishes its metadata,
// registers clients, and authorizes them, for someone who's signed in,
// with a code, which they exchange, with PKCE, for a session's token. It
// needs WithSessions. Clients are redirected to loopback URIs, such as
// http://127.0.0.1:8080/callback, on any port, or to one of the redirects,
// such as https://app.example.com/callback, exactly, as people aren't
// asked to approve them.
func WithOAuth(redirects ...string) Opt {
	return func(o *options) error {
		for _, redirect := range redirects {
			u, err := url.Parse(redirect)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Fragment != "" {
				return httpresponse.ErrBadRequest.Withf("Invalid redirect %q", redirect)
			}
		}
		o.oauth, o.redirects = true, redirects
		return nil
	}
}

// WithSignIn is the path of the sign-in page, such as /login, which
// authorizing a client redirects to, with the path to return to, as
// return, when no one's signed in. Without it, it's the redirect provider's
// sign-in, when there's only one.
func WithSignIn(path string) Opt {
	return func(o *options) error {
		if !localPath(path) {
			return httpresponse.ErrBadRequest.With("The sign-in page is a path on this server, such as /login")
		}
		o.signin = path
		return nil
	}
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// ResourceMetadataPath is the path of the protected resource metadata of
// the API, at prefix, such as /api, which a 401's challenge refers to
func ResourceMetadataPath(prefix string) string {
	return types.JoinPath(pathResourceMetadata, prefix)
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS - PATHS

// registerOAuth registers the metadata, which isn't under the API's prefix,
// and the endpoints, which are
func registerOAuth(router *httprouter.Router, h *handlers, doc *opts.MarkdownDoc) error {
	// Codes are consumed by the sessions, when they can, so a code isn't
	// exchanged again by another server, or after a restart, and else by
	// this server
	if consumer, ok := h.sessions.(store.Consumer); ok {
		h.consumer = consumer
	} else {
		h.consumer = &consumed{codes: map[string]int64{}}
	}
	resource := func(path httprequest.PathItem) {
		path.Tag(tagOAuth)
		path.Get(h.resourceMetadata, func(op httprequest.PathOperation) {
			op.Summary("Get the API's protected resource metadata")
			op.Description(doc.Section(3, "GET /.well-known/oauth-protected-resource").Body)
			op.JSONResponse(http.StatusOK, jsonschema.MustFor[httpclient.ResourceMetadata](), "The metadata")
		})
	}
	paths := []error{
		router.Register(pathServerMetadata, nil, func(path httprequest.PathItem) {
			path.Tag(tagOAuth)
			path.Get(h.serverMetadata, func(op httprequest.PathOperation) {
				op.Summary("Get the authorization server's metadata")
				op.Description(doc.Section(3, "GET /.well-known/oauth-authorization-server").Body)
				op.JSONResponse(http.StatusOK, jsonschema.MustFor[httpclient.ServerMetadata](), "The metadata")
			})
		}),
		router.Register(pathResourceMetadata, nil, resource),
		router.Register("auth/register", nil, func(path httprequest.PathItem) {
			path.Tag(tagOAuth)
			path.Post(h.register, func(op httprequest.PathOperation) {
				op.Summary("Register a client")
				op.Description(doc.Section(3, "POST /auth/register").Body)
				op.RequestBody(jsonschema.MustFor[registerRequest](), types.ContentTypeJSON)
				op.JSONResponse(http.StatusCreated, jsonschema.MustFor[registerResponse](), "The client")
				op.JSONResponse(http.StatusBadRequest, jsonschema.MustFor[oauthError](), "A redirect URI, or other metadata, isn't allowed")
			})
		}),
		router.Register("auth/authorize", nil, func(path httprequest.PathItem) {
			path.Tag(tagOAuth)
			path.Get(h.authorize, func(op httprequest.PathOperation) {
				op.Summary("Authorize a client")
				op.Description(doc.Section(3, "GET /auth/authorize").Body)
				op.Query(jsonschema.MustFor[authorizeQuery]())
				op.Response(http.StatusFound, "", "To the client's redirect URI, with a code, or an error, or else to sign in")
				op.JSONResponse(http.StatusBadRequest, jsonschema.MustFor[oauthError](), "The client, or its redirect URI, isn't valid")
				op.ErrorResponse(http.StatusUnauthorized, "No one's signed in, and there's no sign-in page to send them to")
			})
		}),
		router.Register("auth/token", nil, func(path httprequest.PathItem) {
			path.Tag(tagOAuth)
			path.Post(h.token, func(op httprequest.PathOperation) {
				op.Summary("Exchange a code for a token")
				op.Description(doc.Section(3, "POST /auth/token").Body)
				op.RequestBody(jsonschema.MustFor[tokenRequest](), types.ContentTypeForm)
				op.JSONResponse(http.StatusOK, jsonschema.MustFor[tokenResponse](), "The token")
				op.JSONResponse(http.StatusBadRequest, jsonschema.MustFor[oauthError](), "The code, or its verifier, isn't valid")
				op.JSONResponse(http.StatusUnauthorized, jsonschema.MustFor[oauthError](), "The client isn't valid")
			})
		}),
	}

	// The API's own, as RFC 9728 has it, after the well-known path
	if h.prefix != "" && h.prefix != "/" {
		paths = append(paths, router.Register(ResourceMetadataPath(h.prefix), nil, resource))
	}
	return errors.Join(paths...)
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS - HANDLERS

// resourceMetadata returns the API's protected resource metadata, whose
// authorization server is this one
func (h *handlers) resourceMetadata(w http.ResponseWriter, r *http.Request) {
	origin := h.origin(r)
	httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), httpclient.ResourceMetadata{
		Resource:               h.resourceURL(origin),
		AuthorizationServers:   []string{origin},
		BearerMethodsSupported: []string{"header"},
	})
}

// serverMetadata returns the authorization server's metadata
func (h *handlers) serverMetadata(w http.ResponseWriter, r *http.Request) {
	origin := h.origin(r)
	api := origin + types.JoinPath(h.prefix, "auth")
	httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), httpclient.ServerMetadata{
		Issuer:                            origin,
		AuthorizationEndpoint:             api + "/authorize",
		TokenEndpoint:                     api + "/token",
		RegistrationEndpoint:              api + "/register",
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		TokenEndpointAuthMethodsSupported: []string{"none"},
		IssParameterSupported:             true,
	})
}

// register registers a public client, whose ID is it, sealed, when its
// redirect URIs are allowed
func (h *handlers) register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxRegistration)).Decode(&req); err != nil {
		oauthFail(w, http.StatusBadRequest, "invalid_client_metadata", "The registration isn't JSON")
		return
	}
	switch {
	case len(req.RedirectURIs) == 0:
		oauthFail(w, http.StatusBadRequest, "invalid_redirect_uri", "A client needs a redirect URI")
		return
	case req.TokenEndpointAuthMethod != "" && req.TokenEndpointAuthMethod != "none":
		oauthFail(w, http.StatusBadRequest, "invalid_client_metadata", "Clients are public, so their token_endpoint_auth_method is none")
		return
	case len(req.ResponseTypes) > 0 && !slices.Contains(req.ResponseTypes, "code"):
		oauthFail(w, http.StatusBadRequest, "invalid_client_metadata", "The response type is code")
		return
	case len(req.GrantTypes) > 0 && !slices.Contains(req.GrantTypes, "authorization_code"):
		oauthFail(w, http.StatusBadRequest, "invalid_client_metadata", "The grant type is authorization_code")
		return
	}
	for _, redirect := range req.RedirectURIs {
		if !h.allowedRedirect(redirect) {
			oauthFail(w, http.StatusBadRequest, "invalid_redirect_uri", "The redirect URI "+redirect+" isn't allowed: it's a loopback one, such as http://127.0.0.1:8080/callback, or one the server allows")
			return
		}
	}
	client := oauthClient{Name: req.ClientName, Redirects: req.RedirectURIs, Issued: h.now().Unix()}
	id, err := h.sealer.sealValue(purposeClient, client)
	if err != nil {
		httpresponse.Error(w, httpresponse.ErrInternalError.With(err))
		return
	} else if len(id) > maxClientID {
		oauthFail(w, http.StatusBadRequest, "invalid_client_metadata", "The registration is too large: fewer, or shorter, redirect URIs, or a shorter name")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	httpresponse.JSON(w, http.StatusCreated, httprequest.Indent(r), registerResponse{
		ClientID:                id,
		ClientIDIssuedAt:        client.Issued,
		ClientName:              client.Name,
		RedirectURIs:            client.Redirects,
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
	})
}

// authorize redirects back to the client, with a code for the session of
// whoever's signed in, or else to sign in, which returns here
func (h *handlers) authorize(w http.ResponseWriter, r *http.Request) {
	var query authorizeQuery
	if err := httprequest.Query(r.URL.Query(), &query); err != nil {
		oauthFail(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	// Without a client, and its redirect URI, there's nowhere to say what's
	// wrong but here
	var client oauthClient
	if err := h.sealer.openValue(purposeClient, query.ClientID, &client); err != nil {
		oauthFail(w, http.StatusBadRequest, "invalid_client", "The client isn't registered")
		return
	}
	redirect := query.RedirectURI
	if redirect == "" && len(client.Redirects) == 1 {
		redirect = client.Redirects[0]
	} else if !client.redirects(redirect) {
		oauthFail(w, http.StatusBadRequest, "invalid_request", "The redirect URI isn't the client's")
		return
	}

	// It's allowed now, too, as a redirect can stop being allowed after
	// the client registered
	if !h.allowedRedirect(redirect) {
		oauthFail(w, http.StatusBadRequest, "invalid_request", "The redirect URI isn't allowed")
		return
	}

	// Otherwise, the client is told
	origin := h.origin(r)
	fail := func(code, reason string) {
		redirectTo(w, redirect, url.Values{"error": {code}, "error_description": {reason}, "state": {query.State}, "iss": {origin}})
	}
	switch {
	case query.ResponseType != "code":
		fail("unsupported_response_type", "The response type is code")
		return
	case query.CodeChallenge == "" || query.CodeChallengeMethod != "S256":
		fail("invalid_request", "A PKCE challenge, with the S256 method, is needed")
		return
	case query.Resource != "" && query.Resource != h.resourceURL(origin):
		fail("invalid_target", "The resource is "+h.resourceURL(origin))
		return
	}

	// Whoever's signed in, or else they sign in, and return
	session, err := h.sessions.Session(r.Context(), security.Token(r))
	if errors.Is(err, httpresponse.ErrNotAuthorized) {
		h.signIn(w, r)
		return
	} else if err != nil {
		httpresponse.Error(w, httpresponse.ErrInternalError.With("The session couldn't be checked"))
		return
	}

	// The scopes asked for, which they have, or else all theirs
	scopes := session.Scopes
	if requested := strings.Fields(query.Scope); len(requested) > 0 {
		scopes = slices.DeleteFunc(requested, func(scope string) bool { return !slices.Contains(session.Scopes, scope) })
	}
	code, err := h.sealer.sealValue(purposeCode, oauthCode{
		ID:        provider.NewVerifier(),
		Client:    clientHash(query.ClientID),
		Redirect:  redirect,
		Given:     query.RedirectURI != "",
		Challenge: query.CodeChallenge,
		Resource:  query.Resource,
		User:      session.User,
		Provider:  session.Provider,
		Scopes:    scopes,
		Ends:      session.ExpiresAt.Unix(),
		Expires:   h.now().Add(codeTTL).Unix(),
	})
	if err != nil {
		httpresponse.Error(w, httpresponse.ErrInternalError.With(err))
		return
	}
	redirectTo(w, redirect, url.Values{"code": {code}, "state": {query.State}, "iss": {origin}})
}

// token exchanges a code, once, with the verifier of its challenge, for a
// new session, which ends with the one it was authorized by
func (h *handlers) token(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxForm)
	if err := r.ParseForm(); err != nil {
		oauthFail(w, http.StatusBadRequest, "invalid_request", "The request is a form")
		return
	}
	req := tokenRequest{
		GrantType:    r.PostForm.Get("grant_type"),
		Code:         r.PostForm.Get("code"),
		RedirectURI:  r.PostForm.Get("redirect_uri"),
		ClientID:     r.PostForm.Get("client_id"),
		CodeVerifier: r.PostForm.Get("code_verifier"),
		Resource:     r.PostForm.Get("resource"),
	}
	if req.GrantType != "authorization_code" {
		oauthFail(w, http.StatusBadRequest, "unsupported_grant_type", "The grant is authorization_code")
		return
	}
	var client oauthClient
	if err := h.sealer.openValue(purposeClient, req.ClientID, &client); err != nil {
		oauthFail(w, http.StatusUnauthorized, "invalid_client", "The client isn't registered")
		return
	}
	now := h.now()
	var code oauthCode
	if err := h.sealer.openValue(purposeCode, req.Code, &code); err != nil || now.Unix() > code.Expires {
		oauthFail(w, http.StatusBadRequest, "invalid_grant", "The code isn't valid, or has expired")
		return
	}
	resource := code.Resource
	if resource == "" {
		resource = h.resourceURL(h.origin(r))
	}
	switch {
	case code.Client != clientHash(req.ClientID):
		oauthFail(w, http.StatusBadRequest, "invalid_grant", "The code isn't the client's")
		return
	case (code.Given || req.RedirectURI != "") && req.RedirectURI != code.Redirect:
		oauthFail(w, http.StatusBadRequest, "invalid_grant", "The redirect URI isn't the code's")
		return
	case !verifies(req.CodeVerifier, code.Challenge):
		oauthFail(w, http.StatusBadRequest, "invalid_grant", "The verifier isn't the code's challenge's")
		return
	case req.Resource != "" && req.Resource != resource:
		oauthFail(w, http.StatusBadRequest, "invalid_target", "The resource isn't the code's")
		return
	case !now.Before(time.Unix(code.Ends, 0)):
		oauthFail(w, http.StatusBadRequest, "invalid_grant", "The session the code was for has ended")
		return
	}
	if err := h.consumer.Consume(r.Context(), code.ID, time.Unix(code.Expires, 0)); errors.Is(err, httpresponse.ErrConflict) {
		oauthFail(w, http.StatusBadRequest, "invalid_grant", "The code has been exchanged")
		return
	} else if err != nil {
		httpresponse.Error(w, httpresponse.ErrInternalError.With("The code couldn't be checked"))
		return
	}

	// A session of its own, for the client, which can be revoked
	token, err := h.sessions.Create(r.Context(), schema.Session{
		User:      code.User,
		Provider:  code.Provider,
		Client:    client.Name,
		Scopes:    code.Scopes,
		CreatedAt: now,
		ExpiresAt: time.Unix(code.Ends, 0),
	})
	if err != nil {
		httpresponse.Error(w, httpresponse.ErrInternalError.With("The session couldn't be made"))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), tokenResponse{
		AccessToken: token.Token,
		TokenType:   "Bearer",
		ExpiresIn:   int64(token.ExpiresAt.Sub(now).Seconds()),
		Scope:       strings.Join(token.Scopes, " "),
	})
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// signIn redirects to sign in, which returns to the request, or else says
// someone needs to, when there's nowhere to
func (h *handlers) signIn(w http.ResponseWriter, r *http.Request) {
	path := h.signin
	if path == "" {
		var redirects []string
		for _, p := range h.providers {
			if _, ok := p.(provider.RedirectProvider); ok {
				redirects = append(redirects, p.Meta().Name)
			}
		}
		if len(redirects) != 1 {
			httpresponse.Error(w, httpresponse.ErrNotAuthorized.With("Sign in first, then authorize the client"))
			return
		}
		path = types.JoinPath(h.prefix, "auth/"+url.PathEscape(redirects[0])+"/login")
	}
	u, _ := url.Parse(path)
	query := u.Query()
	query.Set("return", r.URL.RequestURI())
	u.RawQuery = query.Encode()
	w.Header().Set("Location", u.String())
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusFound)
}

// origin is the scheme and host the server is reached at: the base URL's,
// or else the request's
func (h *handlers) origin(r *http.Request) string {
	if h.base != nil {
		return h.base.Scheme + "://" + h.base.Host
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// resourceURL is the API's URL, which tokens are for
func (h *handlers) resourceURL(origin string) string {
	if h.prefix == "" || h.prefix == "/" {
		return origin
	}
	return origin + h.prefix
}

// allowedRedirect returns whether a client can be redirected to the URI:
// a loopback one, as RFC 8252 has it, or one which is allowed, exactly
func (h *handlers) allowedRedirect(redirect string) bool {
	if slices.Contains(h.redirects, redirect) {
		return true
	}
	return loopback(redirect)
}

// redirects returns whether the URI is one of the client's, where a
// loopback one's port can differ, as RFC 8252 has it
func (c oauthClient) redirects(redirect string) bool {
	if slices.Contains(c.Redirects, redirect) {
		return true
	}
	if !loopback(redirect) {
		return false
	}
	u, _ := url.Parse(redirect)
	for _, registered := range c.Redirects {
		if r, err := url.Parse(registered); err == nil && loopback(registered) && r.Hostname() == u.Hostname() && r.Path == u.Path && r.RawQuery == u.RawQuery {
			return true
		}
	}
	return false
}

// Consume consumes a code's ID, until it expires, or returns conflict
func (c *consumed) Consume(_ context.Context, id string, expires time.Time) error {
	c.Lock()
	defer c.Unlock()
	now := time.Now().Unix()
	for key, until := range c.codes {
		if now > until {
			delete(c.codes, key)
		}
	}
	if _, exists := c.codes[id]; exists {
		return httpresponse.ErrConflict.With("It's been used")
	}
	c.codes[id] = expires.Unix()
	return nil
}

// clientHash is a client's ID, hashed, which a code has, rather than the
// ID, so it's shorter
func clientHash(id string) string {
	sum := sha256.Sum256([]byte(id))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// loopback returns whether the URI is a loopback redirect, with http, to
// 127.0.0.1, ::1, or localhost, on any port
func loopback(redirect string) bool {
	u, err := url.Parse(redirect)
	if err != nil || u.Scheme != "http" || u.Fragment != "" || u.User != nil {
		return false
	}
	if u.Hostname() == "localhost" {
		return true
	}
	ip := net.ParseIP(u.Hostname())
	return ip != nil && ip.IsLoopback()
}

// verifies returns whether the verifier is the S256 challenge's
func verifies(verifier, challenge string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(challenge)) == 1
}

// redirectTo redirects to the URI, with the values in its query, which
// are set
func redirectTo(w http.ResponseWriter, redirect string, values url.Values) {
	u, _ := url.Parse(redirect)
	query := u.Query()
	for key, value := range values {
		if len(value) > 0 && value[0] != "" {
			query.Set(key, value[0])
		}
	}
	u.RawQuery = query.Encode()
	w.Header().Set("Location", u.String())
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusFound)
}

// oauthFail writes an OAuth error, with the status
func oauthFail(w http.ResponseWriter, status int, code, reason string) {
	w.Header().Set("Cache-Control", "no-store")
	_ = httpresponse.JSON(w, status, 0, oauthError{Error: code, Description: reason})
}
