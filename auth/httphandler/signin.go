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
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"

	// Packages
	goauth "github.com/mutablelogic/go-auth"
	provider "github.com/mutablelogic/go-auth/auth/provider"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	httprouter "github.com/mutablelogic/go-server/pkg/httprouter"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
	opts "github.com/mutablelogic/go-server/pkg/openapi"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// handlers sign in with the providers
type handlers struct {
	providers []provider.Provider
	byName    map[string]provider.Provider
	sealer    *sealer
	options
	prefix string
}

// providerParams is the path parameter of a provider
type providerParams struct {
	Provider string `json:"provider" help:"Name of the provider, such as google"`
}

// passwordRequest is the body of signing in with a password provider
type passwordRequest struct {
	Username string `json:"username" help:"Username" required:""`
	Password string `json:"password" help:"Password" required:""`
}

// callbackQuery is the query a redirect provider returns with
type callbackQuery struct {
	Code             string `json:"code,omitempty" help:"Authorization code, to exchange"`
	State            string `json:"state,omitempty" help:"State of the sign-in, which must be its cookie's"`
	Error            string `json:"error,omitempty" help:"Error, when the provider refused the sign-in, such as access_denied"`
	ErrorDescription string `json:"error_description,omitempty" help:"Why the provider refused the sign-in"`
}

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

// cookieName is the name of the cookie with the state of a sign-in
const cookieName = "goauth_signin"

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS - PATHS

// registerSignIn registers listing the providers, signing in with one, and
// a redirect provider's callback
func registerSignIn(router *httprouter.Router, h *handlers, doc *opts.MarkdownDoc) error {
	h.prefix = router.Prefix()
	return errors.Join(
		router.Register("auth/provider", nil, func(path httprequest.PathItem) {
			path.Tag(tagSignIn)
			path.Get(func(w http.ResponseWriter, r *http.Request) {
				httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), Providers(h.providers))
			}, func(op httprequest.PathOperation) {
				op.Summary("List the providers")
				op.Description(doc.Section(3, "GET /auth/provider").Body)
				op.JSONResponse(http.StatusOK, jsonschema.MustFor[[]schema.ProviderMeta](), "The providers")
			})
		}),
		router.Register("auth/{provider}/login", jsonschema.MustFor[providerParams](), func(path httprequest.PathItem) {
			path.Tag(tagSignIn)
			path.Get(h.login, func(op httprequest.PathOperation) {
				op.Summary("Sign in with a redirect provider")
				op.Description(doc.Section(3, "GET /auth/{provider}/login").Body)
				op.Response(http.StatusFound, "", "To the provider's sign-in page")
				op.ErrorResponse(http.StatusNotFound, "No redirect provider with the name")
				op.ErrorResponse(http.StatusBadGateway, "The provider can't be reached")
			})
			path.Post(h.password, func(op httprequest.PathOperation) {
				op.Summary("Sign in with a password provider")
				op.Description(doc.Section(3, "POST /auth/{provider}/login").Body)
				op.RequestBody(jsonschema.MustFor[passwordRequest](), types.ContentTypeJSON, types.ContentTypeForm)
				op.JSONResponse(http.StatusOK, jsonschema.MustFor[schema.Identity](), "Who signed in")
				op.ErrorResponse(http.StatusBadRequest, "No username or password")
				op.ErrorResponse(http.StatusUnauthorized, "The username or password isn't right")
				op.ErrorResponse(http.StatusNotFound, "No password provider with the name")
			})
		}),
		router.Register("auth/{provider}/callback", jsonschema.MustFor[providerParams](), func(path httprequest.PathItem) {
			path.Tag(tagSignIn)
			path.Get(h.callback, func(op httprequest.PathOperation) {
				op.Summary("Return from a redirect provider")
				op.Description(doc.Section(3, "GET /auth/{provider}/callback").Body)
				op.Query(jsonschema.MustFor[callbackQuery]())
				op.JSONResponse(http.StatusOK, jsonschema.MustFor[schema.Identity](), "Who signed in")
				op.ErrorResponse(http.StatusBadRequest, "No code")
				op.ErrorResponse(http.StatusUnauthorized, "The provider refused the sign-in, or its state isn't the sign-in's")
				op.ErrorResponse(http.StatusNotFound, "No redirect provider with the name")
				op.ErrorResponse(http.StatusBadGateway, "The provider can't be reached")
			})
		}),
	)
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS - HANDLERS

// login redirects to a redirect provider's sign-in page, with the state and
// verifier of the sign-in in a sealed cookie, for the provider's paths
func (h *handlers) login(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("provider")
	p, ok := h.byName[name].(provider.RedirectProvider)
	if !ok {
		httpresponse.Error(w, httpresponse.ErrNotFound.Withf("No redirect provider %q", name))
		return
	}
	in := signin{Provider: name, State: provider.NewVerifier(), Verifier: provider.NewVerifier(), Expires: h.now().Add(h.ttl).Unix()}
	authURL, err := p.AuthCodeURL(r.Context(), h.callbackURL(r, name), in.State, in.Verifier)
	if err != nil {
		httpresponse.Error(w, goauth.HTTPError(err))
		return
	}
	value, err := h.sealer.seal(in)
	if err != nil {
		httpresponse.Error(w, httpresponse.ErrInternalError.With(err))
		return
	}
	http.SetCookie(w, h.cookie(r, name, value, int(h.ttl.Seconds())))
	w.Header().Set("Location", authURL)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusFound)
}

// callback exchanges a redirect provider's code, when its state is the
// sign-in's, from its cookie, which is cleared
func (h *handlers) callback(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("provider")
	p, ok := h.byName[name].(provider.RedirectProvider)
	if !ok {
		httpresponse.Error(w, httpresponse.ErrNotFound.Withf("No redirect provider %q", name))
		return
	}
	var query callbackQuery
	if err := httprequest.Query(r.URL.Query(), &query); err != nil {
		httpresponse.Error(w, httpresponse.ErrBadRequest.Withf("%v", err))
		return
	}

	// The sign-in is only completed once
	http.SetCookie(w, h.cookie(r, name, "", -1))
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		httpresponse.Error(w, httpresponse.ErrNotAuthorized.With("There's no sign-in, or it's been completed"))
		return
	}
	in, err := h.sealer.open(cookie.Value, name, h.now())
	if err != nil {
		httpresponse.Error(w, httpresponse.ErrNotAuthorized.With(err))
		return
	}
	switch {
	case query.Error != "":
		reason := query.ErrorDescription
		if reason == "" {
			reason = query.Error
		}
		httpresponse.Error(w, httpresponse.ErrNotAuthorized.Withf("%s refused the sign-in: %s", p.Meta().Label, reason))
		return
	case subtle.ConstantTimeCompare([]byte(query.State), []byte(in.State)) != 1:
		httpresponse.Error(w, httpresponse.ErrNotAuthorized.With("The state isn't the sign-in's"))
		return
	case query.Code == "":
		httpresponse.Error(w, httpresponse.ErrBadRequest.With("No code"))
		return
	}
	h.exchange(w, r, p, schema.Credential{Code: query.Code, CodeVerifier: in.Verifier, RedirectURL: h.callbackURL(r, name)})
}

// password signs in with a password provider
func (h *handlers) password(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("provider")
	p, ok := h.byName[name]
	if _, redirect := p.(provider.RedirectProvider); !ok || redirect {
		httpresponse.Error(w, httpresponse.ErrNotFound.Withf("No password provider %q", name))
		return
	}
	var req passwordRequest
	if err := httprequest.Read(r, &req); err != nil {
		httpresponse.Error(w, httpresponse.ErrBadRequest.Withf("%v", err))
		return
	}
	h.exchange(w, r, p, schema.Credential{Username: req.Username, Password: req.Password})
}

// exchange exchanges the credential for an identity, and the identity for
// the response
func (h *handlers) exchange(w http.ResponseWriter, r *http.Request, p provider.Provider, credential schema.Credential) {
	identity, err := p.Exchange(r.Context(), credential)
	if err != nil {
		httpresponse.Error(w, goauth.HTTPError(err))
		return
	}
	result, err := h.options.exchange(r.Context(), identity)
	if err != nil {
		httpresponse.Error(w, goauth.HTTPError(err))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), result)
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// callbackURL is the absolute URL a provider redirects back to: the base
// URL, or else the request's scheme and host, with the provider's path
func (h *handlers) callbackURL(r *http.Request, name string) string {
	scheme, host := "http", r.Host
	if r.TLS != nil {
		scheme = "https"
	}
	if h.base != nil {
		scheme, host = h.base.Scheme, h.base.Host
	}
	return scheme + "://" + host + types.JoinPath(h.prefix, "auth/"+url.PathEscape(name)+"/callback")
}

// cookie returns the cookie of a sign-in with the provider, for its paths,
// which is secure when the server is reached with https, and is removed
// when maxAge is negative
func (h *handlers) cookie(r *http.Request, name, value string, maxAge int) *http.Cookie {
	secure := r.TLS != nil || (h.base != nil && h.base.Scheme == "https")
	return &http.Cookie{
		Name:     cookieName,
		Value:    value,
		Path:     types.JoinPath(h.prefix, "auth/"+url.PathEscape(name)),
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
}
