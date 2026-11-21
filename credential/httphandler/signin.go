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
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"

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

// signIn is an authorization server, whose sign-ins are stored as the
// credentials whose keys have the prefix, with the client which is the
// value of a credential
type signIn struct {
	prefix string
	server authclient.ServerMetadata
	client string
	web    *webSignIn
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// WithSignIn stores the sign-ins with the server, such as Google, as the
// credentials whose keys have the prefix, such as GOOGLE_, other than the
// client's: a code, which a client authorized at a loopback address, is
// exchanged with the client, which is the value of the credential with the
// client key, as its client_id and client_secret, and the grant is stored,
// without the secret. It can be given more than once: a key is the sign-in
// of the server with the longest of its prefixes, and no key of a client is
// a sign-in.
func WithSignIn(prefix string, server authclient.ServerMetadata, client string) Opt {
	return func(o *options) {
		o.signIns = append(o.signIns, signIn{prefix: prefix, server: server, client: client})
	}
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS - PATHS

// registerSignIn registers storing sign-ins, when there are servers whose
// sign-ins are stored
func registerSignIn(router *httprouter.Router, provider credential.CredentialProvider, signIns []signIn, auth bool, doc *opts.MarkdownDoc, notify notifyFunc) error {
	if len(signIns) == 0 {
		return nil
	}
	return router.Register("credential/{key}/signin", jsonschema.MustFor[keyParams](), func(path httprequest.PathItem) {
		path.Tag(tag)
		path.Post(func(w http.ResponseWriter, r *http.Request) {
			exchange(provider, signIns, w, r, notify)
		}, func(op httprequest.PathOperation) {
			op.Summary("Store a sign-in")
			op.Description(doc.Section(3, "POST /credential/{key}/signin").Body)
			op.RequestBody(jsonschema.MustFor[credential.CredentialCode]())
			op.JSONResponse(http.StatusOK, jsonschema.MustFor[credential.CredentialSignIn](), "Stored sign-in, without its tokens")
			op.ErrorResponse(http.StatusBadRequest, "Invalid key or request body, a key which isn't a sign-in's, a redirect which isn't a loopback address, or a code which the server refused")
			op.ErrorResponse(http.StatusForbidden, "The backend refused the write")
			op.ErrorResponse(http.StatusServiceUnavailable, "No client, a client which the server refused, or the server failed")
			security(op, auth, credential.ScopeCredentialWrite)
		})
	})
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS - HANDLERS

// exchange exchanges the code of a sign-in, with the client's secret, and
// stores the grant, under the key's lock
func exchange(provider credential.CredentialProvider, signIns []signIn, w http.ResponseWriter, r *http.Request, notify notifyFunc) {
	key := r.PathValue("key")
	var req credential.CredentialCode
	if !types.IsIdentifier(key) {
		httpresponse.Error(w, httpresponse.ErrBadRequest.Withf("credential key %q must be an identifier", key))
		return
	} else if err := httprequest.Read(r, &req); err != nil {
		httpresponse.Error(w, httpresponse.ErrBadRequest.Withf("%v", err))
		return
	} else if !isLoopback(req.RedirectURI) {
		httpresponse.Error(w, httpresponse.ErrBadRequest.Withf("redirect URI %q isn't a loopback address", req.RedirectURI), key)
		return
	}
	s := match(signIns, key)
	if s == nil {
		httpresponse.Error(w, httpresponse.ErrBadRequest.Withf("credential %q isn't a sign-in's", key), key)
		return
	}

	// The client, with its secret, which is read each time, so a changed
	// secret is used without a restart
	value, err := provider.Get(r.Context(), s.client)
	if errors.Is(err, auth.ErrNotFound) {
		httpresponse.Error(w, httpresponse.ErrServiceUnavailable.Withf("no %q credential, of the OAuth client of %s", s.client, s.server.Issuer), key)
		return
	} else if err != nil {
		httpresponse.Error(w, auth.HTTPError(err), key)
		return
	}
	client, err := authclient.ParseRegistration(value)
	if err != nil {
		httpresponse.Error(w, httpresponse.ErrServiceUnavailable.Withf("credential %q: %v", s.client, err), key)
		return
	}

	// Exchange the code. A client which the server refuses, such as one
	// whose secret is wrong, is the server's problem, not the request's.
	grant, err := authclient.ExchangeCode(r.Context(), s.server, *client, authclient.SignInCode{Credential: key, Code: req.Code, CodeVerifier: req.CodeVerifier, RedirectURI: req.RedirectURI})
	var retrieve *oauth2.RetrieveError
	if errors.As(err, &retrieve) && (retrieve.ErrorCode == "invalid_client" || retrieve.ErrorCode == "unauthorized_client") {
		httpresponse.Error(w, httpresponse.ErrServiceUnavailable.Withf("%s refused the client of %q, so check its client_id and client_secret: %v", s.server.Issuer, s.client, err), key)
		return
	} else if err != nil {
		httpresponse.Error(w, auth.HTTPError(err), key)
		return
	}

	// Store it, under the key's lock
	data, err := json.Marshal(grant)
	if err != nil {
		httpresponse.Error(w, err, key)
		return
	}
	unlock := credential.Lock(key)
	err = provider.Set(r.Context(), key, data)
	unlock()
	if err != nil {
		httpresponse.Error(w, auth.HTTPError(err), key)
		return
	}
	notify(schema.ChangeUpdate, key)
	httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), credential.CredentialSignIn{Key: key, Issuer: grant.Server.Issuer, Scopes: grant.Scopes})
}

// match returns the server whose sign-ins the key is, of the longest of the
// prefixes it has, or nil, when it has none, or it's the key of any server's
// client, or web client, so a sign-in never replaces a client
func match(signIns []signIn, key string) *signIn {
	for _, s := range signIns {
		if key == s.client || (s.web != nil && key == s.web.client) {
			return nil
		}
	}
	var result *signIn
	for i := range signIns {
		if s := &signIns[i]; strings.HasPrefix(key, s.prefix) && (result == nil || len(s.prefix) > len(result.prefix)) {
			result = s
		}
	}
	return result
}

// isLoopback returns true when the URI is http, of a loopback address, such
// as http://127.0.0.1:8085/callback
func isLoopback(uri string) bool {
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "http" {
		return false
	}
	if u.Hostname() == "localhost" {
		return true
	}
	ip := net.ParseIP(u.Hostname())
	return ip != nil && ip.IsLoopback()
}
