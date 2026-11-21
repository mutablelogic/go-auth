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
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	authclient "github.com/mutablelogic/go-auth/auth/httpclient"
	credential "github.com/mutablelogic/go-auth/credential"
	schema "github.com/mutablelogic/go-server/broadcaster/schema"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	httprouter "github.com/mutablelogic/go-server/pkg/httprouter"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
	opts "github.com/mutablelogic/go-server/pkg/openapi"
	types "github.com/mutablelogic/go-server/pkg/types"
	oauth2 "golang.org/x/oauth2"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// webSignIn is the web client of the sign-ins of a server, of their prefix,
// which redirects to the server's callback, with the options of the URL the
// person signs in at, such as Google's access_type=offline
type webSignIn struct {
	prefix string
	client string
	opts   []oauth2.AuthCodeOption
}

// authorization is a sign-in which is asked for, and not done yet: the key
// it's stored as, the PKCE verifier of its code, the URL of the callback it
// redirects to, which the code is exchanged with, the server, and its web
// client, until it expires
type authorization struct {
	key      string
	verifier string
	redirect string
	server   authclient.ServerMetadata
	client   string
	expires  time.Time
}

// callbackQuery is the query of the callback, which the authorization
// server redirects to
type callbackQuery struct {
	State            string `json:"state,omitempty" help:"State of the sign-in, which was asked for"`
	Code             string `json:"code,omitempty" help:"Code of the sign-in, which is exchanged"`
	Error            string `json:"error,omitempty" help:"Why the person isn't signed in, such as access_denied"`
	ErrorDescription string `json:"error_description,omitempty" help:"What the error is"`
}

// authorizations are the sign-ins which are asked for, by their state, each
// of which is done once, at most, before it expires
type authorizations struct {
	sync.Mutex
	pending map[string]authorization
}

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

const (
	// authorizationTTL is how long a sign-in which is asked for can be done
	authorizationTTL = 10 * time.Minute

	// callbackPath is the path of the callback, which a web client
	// redirects to, beneath the API's prefix
	callbackPath = "credential/callback"

	// SignInMessage is the type of the message the callback's page posts to
	// the window which opened it, of the key, and whether it's signed in,
	// or why it isn't
	SignInMessage = "credential-signin"
)

// callbackPage is the page of the callback, which tells the window which
// opened it, of the same origin, whether the person signed in, and closes
var callbackPage = template.Must(template.New("callback").Parse(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>{{if .OK}}Signed in{{else}}Not signed in{{end}}</title></head>
<body style="font-family: sans-serif; padding: 2rem">
<p>{{if .OK}}You're signed in. You can close this window.{{else}}You aren't signed in: {{.Error}}{{end}}</p>
<script>
(function () {
	var message = {type: {{.Type}}, key: {{.Key}}, ok: {{.OK}}, error: {{.Error}}};
	if (window.opener) {
		window.opener.postMessage(message, window.location.origin);
		{{if .OK}}window.close();{{end}}
	}
})();
</script>
</body></html>
`))

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// WithWebSignIn signs in, in a browser, with the web client of the sign-ins
// of the server of the prefix (see WithSignIn), which is the value of the
// credential with the client key, as its client_id and client_secret, such
// as the file Google's console downloads of a web application's client.
// POST credential/{key}/authorize returns the URL a person signs in at,
// which redirects to the server's callback, credential/callback, which is
// registered with the client, which exchanges the code, and stores the
// grant. The options are of the URL, such as Google's access_type=offline,
// so the grant can be refreshed.
func WithWebSignIn(prefix, client string, opts ...oauth2.AuthCodeOption) Opt {
	return func(o *options) {
		o.webSignIns = append(o.webSignIns, webSignIn{prefix: prefix, client: client, opts: opts})
	}
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS - PATHS

// registerWebSignIn registers signing in, in a browser, when there are web
// clients of servers whose sign-ins are stored: asking for the URL to sign
// in at, and the callback, which needs no scopes, as its state, which is
// random, and done once, is the sign-in's
func registerWebSignIn(router *httprouter.Router, provider credential.CredentialProvider, signIns []signIn, webs []webSignIn, auth bool, doc *opts.MarkdownDoc, notify notifyFunc) error {
	if len(signIns) == 0 || len(webs) == 0 {
		return nil
	}
	pending := &authorizations{pending: make(map[string]authorization)}
	return errors.Join(
		router.Register("credential/{key}/authorize", jsonschema.MustFor[keyParams](), func(path httprequest.PathItem) {
			path.Tag(tag)
			path.Post(func(w http.ResponseWriter, r *http.Request) {
				authorize(provider, signIns, webs, pending, w, r)
			}, func(op httprequest.PathOperation) {
				op.Summary("Sign in, in a browser")
				op.Description(doc.Section(3, "POST /credential/{key}/authorize").Body)
				op.RequestBody(jsonschema.MustFor[credential.CredentialAuthorize]())
				op.JSONResponse(http.StatusOK, jsonschema.MustFor[credential.CredentialAuthorization](), "URL to sign in at")
				op.ErrorResponse(http.StatusBadRequest, "Invalid key or request body, a key which isn't a sign-in's, a server without a web client, or a redirect which isn't the server's callback")
				op.ErrorResponse(http.StatusServiceUnavailable, "No web client, or one which isn't a client")
				security(op, auth, credential.ScopeCredentialWrite)
			})
		}),
		router.Register(callbackPath, nil, func(path httprequest.PathItem) {
			path.Tag(tag)
			path.Get(func(w http.ResponseWriter, r *http.Request) {
				callback(provider, pending, w, r, notify)
			}, func(op httprequest.PathOperation) {
				op.Summary("Sign-in callback")
				op.Description(doc.Section(3, "GET /credential/callback").Body)
				op.Query(jsonschema.MustFor[callbackQuery]())
				op.Response(http.StatusOK, "text/html", "Page which says the person signed in, and tells the window which opened it")
				op.Response(http.StatusBadRequest, "text/html", "Page which says why the person isn't signed in: a state which isn't asked for, or expired, the person refused, or the server refused the code")
				op.Response(http.StatusInternalServerError, "text/html", "Page which says the sign-in couldn't be stored")
				op.Response(http.StatusServiceUnavailable, "text/html", "Page which says there's no web client, or it isn't one")
			})
		}),
	)
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS - HANDLERS

// authorize returns the URL a person signs in at, with the web client of
// the key's server, which redirects to the callback, of a state, and a PKCE
// verifier, which are kept until the callback, or they expire
func authorize(provider credential.CredentialProvider, signIns []signIn, webs []webSignIn, pending *authorizations, w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	var req credential.CredentialAuthorize
	if !types.IsIdentifier(key) {
		httpresponse.Error(w, httpresponse.ErrBadRequest.Withf("credential key %q must be an identifier", key))
		return
	} else if err := httprequest.Read(r, &req); err != nil {
		httpresponse.Error(w, httpresponse.ErrBadRequest.Withf("%v", err))
		return
	} else if !isCallback(req.RedirectURI) {
		httpresponse.Error(w, httpresponse.ErrBadRequest.Withf("redirect URI %q isn't the server's callback, %s", req.RedirectURI, callbackPath), key)
		return
	}
	s := match(signIns, key)
	if s == nil {
		httpresponse.Error(w, httpresponse.ErrBadRequest.Withf("credential %q isn't a sign-in's", key), key)
		return
	}
	web := webOf(webs, s.prefix)
	if web == nil || key == web.client {
		httpresponse.Error(w, httpresponse.ErrBadRequest.Withf("%s has no web client, so sign in with a loopback address", s.server.Issuer), key)
		return
	}

	// The web client, without its secret, which is read when the code is
	// exchanged
	value, err := provider.Get(r.Context(), web.client)
	if errors.Is(err, auth.ErrNotFound) {
		httpresponse.Error(w, httpresponse.ErrServiceUnavailable.Withf("no %q credential, of the web client of %s", web.client, s.server.Issuer), key)
		return
	} else if err != nil {
		httpresponse.Error(w, auth.HTTPError(err), key)
		return
	}
	client, err := authclient.ParseRegistration(value)
	if err != nil {
		httpresponse.Error(w, httpresponse.ErrServiceUnavailable.Withf("credential %q: %v", web.client, err), key)
		return
	}

	// The state, and verifier, which are kept, and the URL
	state, verifier := random(), oauth2.GenerateVerifier()
	pending.add(state, authorization{key: key, verifier: verifier, redirect: req.RedirectURI, server: s.server, client: web.client, expires: time.Now().Add(authorizationTTL)})
	signIn := authclient.SignIn{Server: s.server, ClientID: client.ClientID, Scopes: req.Scopes, Credential: key}
	httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), credential.CredentialAuthorization{URL: signIn.AuthCodeURL(req.RedirectURI, state, verifier, web.opts...)})
}

// callback exchanges the code of a sign-in which was asked for, of its
// state, with the web client, and stores the grant, and returns a page
// which tells the window which opened it
func callback(provider credential.CredentialProvider, pending *authorizations, w http.ResponseWriter, r *http.Request, notify notifyFunc) {
	query := r.URL.Query()
	a, exists := pending.take(query.Get("state"))
	if !exists {
		page(w, http.StatusBadRequest, "", errors.New("the sign-in expired, or was done already, so sign in again"))
		return
	} else if e := query.Get("error"); e != "" {
		page(w, http.StatusBadRequest, a.key, errors.New(strings.TrimSpace(e+" "+query.Get("error_description"))))
		return
	}

	// The web client, with its secret
	value, err := provider.Get(r.Context(), a.client)
	if err != nil {
		page(w, http.StatusServiceUnavailable, a.key, err)
		return
	}
	client, err := authclient.ParseRegistration(value)
	if err != nil {
		page(w, http.StatusServiceUnavailable, a.key, err)
		return
	}

	// Exchange the code, and store the grant, under the key's lock
	grant, err := authclient.ExchangeCode(r.Context(), a.server, *client, authclient.SignInCode{Credential: a.key, Code: query.Get("code"), CodeVerifier: a.verifier, RedirectURI: a.redirect})
	if err != nil {
		page(w, http.StatusBadRequest, a.key, err)
		return
	}
	data, err := json.Marshal(grant)
	if err != nil {
		page(w, http.StatusInternalServerError, a.key, err)
		return
	}
	unlock := credential.Lock(a.key)
	err = provider.Set(r.Context(), a.key, data)
	unlock()
	if err != nil {
		page(w, http.StatusInternalServerError, a.key, err)
		return
	}
	notify(schema.ChangeUpdate, a.key)
	page(w, http.StatusOK, a.key, nil)
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// add keeps a sign-in which is asked for, of its state, and forgets those
// which expired
func (a *authorizations) add(state string, value authorization) {
	a.Lock()
	defer a.Unlock()
	now := time.Now()
	for s, pending := range a.pending {
		if now.After(pending.expires) {
			delete(a.pending, s)
		}
	}
	a.pending[state] = value
}

// take returns the sign-in which was asked for, of its state, once, unless
// it expired
func (a *authorizations) take(state string) (authorization, bool) {
	a.Lock()
	defer a.Unlock()
	value, exists := a.pending[state]
	delete(a.pending, state)
	return value, exists && state != "" && time.Now().Before(value.expires)
}

// page writes the callback's page, of whether the key is signed in, or why
// it isn't, which tells the window which opened it
func page(w http.ResponseWriter, status int, key string, err error) {
	message := ""
	if err != nil {
		message = err.Error()
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = callbackPage.Execute(w, struct {
		Type, Key, Error string
		OK               bool
	}{Type: SignInMessage, Key: key, Error: message, OK: err == nil})
}

// webOf returns the web client of the sign-ins of the prefix, or nil
func webOf(webs []webSignIn, prefix string) *webSignIn {
	for i := range webs {
		if webs[i].prefix == prefix {
			return &webs[i]
		}
	}
	return nil
}

// isCallback returns true when the URI is http, or https, of the server's
// callback, of its path, which the web client has registered
func isCallback(uri string) bool {
	u, err := url.Parse(uri)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return false
	}
	return strings.HasSuffix(u.Path, "/"+callbackPath) && u.RawQuery == "" && u.Fragment == ""
}

// random returns a random state, of 32 bytes, URL-safe
func random() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
