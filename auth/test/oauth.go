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


package test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// OAuth is a fake resource, at ResourcePath, which needs to be authorized,
// and its authorization server, which registers clients, approves their
// authorizations, as a person would, and exchanges codes, with their PKCE
// verifiers, and refresh tokens, for tokens
type OAuth struct {
	*httptest.Server

	mu        sync.Mutex
	n         int
	clients   map[string][]string // Each client's redirect URIs
	secrets   map[string]string   // The secrets of the clients which have them
	codes     map[string]grant    // The codes which are approved, and not exchanged
	tokens    map[string]bool     // The access tokens which are valid
	refreshes map[string]bool     // The refresh tokens which are valid
}

// grant is a code which was approved, for a client, its redirect URI, and
// its PKCE challenge, and resource
type grant struct {
	client, redirect, challenge, resource string
}

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

// ResourcePath is the path of the fake's resource, which needs a token
const ResourcePath = "/resource"

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// NewOAuth returns a fake resource and authorization server, which is
// closed when the test ends
func NewOAuth(t testing.TB) *OAuth {
	t.Helper()
	o := &OAuth{clients: map[string][]string{}, secrets: map[string]string{}, codes: map[string]grant{}, tokens: map[string]bool{}, refreshes: map[string]bool{}}
	o.Server = httptest.NewServer(http.HandlerFunc(o.serve))
	t.Cleanup(o.Close)
	return o
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// ResourceURL is the URL of the fake's resource
func (o *OAuth) ResourceURL() string {
	return o.URL + ResourcePath
}

// Approve approves the authorization URL, as a person would, and returns
// the URL it redirects to, with a code, and its state, or an error, when
// it isn't a valid request, such as one without S256
func (o *OAuth) Approve(authorizeURL string) (string, error) {
	u, err := url.Parse(authorizeURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	o.mu.Lock()
	defer o.mu.Unlock()
	client, redirect := q.Get("client_id"), q.Get("redirect_uri")
	if q.Get("response_type") != "code" {
		return "", fmt.Errorf("response_type isn't code")
	} else if !slices.Contains(o.clients[client], redirect) {
		return "", fmt.Errorf("redirect_uri %q isn't the client's", redirect)
	} else if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		return "", fmt.Errorf("no S256 code challenge")
	} else if q.Get("resource") != o.ResourceURL() {
		return "", fmt.Errorf("resource %q isn't the fake's", q.Get("resource"))
	}
	o.n++
	code := fmt.Sprintf("code-%d", o.n)
	o.codes[code] = grant{client: client, redirect: redirect, challenge: q.Get("code_challenge"), resource: q.Get("resource")}
	to, err := url.Parse(redirect)
	if err != nil {
		return "", err
	}
	values := to.Query()
	values.Set("code", code)
	values.Set("state", q.Get("state"))
	to.RawQuery = values.Encode()
	return to.String(), nil
}

// Client adds a client, with its secret, and redirect URIs, as one which
// is registered beforehand, rather than dynamically, would be
func (o *OAuth) Client(id, secret string, redirects ...string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.clients[id] = redirects
	if secret != "" {
		o.secrets[id] = secret
	}
}

// Revoke makes every token the server issued invalid, so it needs to be
// authorized again
func (o *OAuth) Revoke() {
	o.mu.Lock()
	defer o.mu.Unlock()
	clear(o.tokens)
	clear(o.refreshes)
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// serve serves the authorization server, and the resource, with a token
func (o *OAuth) serve(w http.ResponseWriter, r *http.Request) {
	base := o.URL
	switch r.URL.Path {
	case "/.well-known/oauth-protected-resource" + ResourcePath, "/.well-known/oauth-protected-resource":
		writeJSON(w, http.StatusOK, map[string]any{"resource": o.ResourceURL(), "authorization_servers": []string{base}, "resource_name": "Fake", "scopes_supported": []string{"read"}})
	case "/.well-known/oauth-authorization-server":
		writeJSON(w, http.StatusOK, map[string]any{
			"issuer":                           base,
			"authorization_endpoint":           base + "/authorize",
			"token_endpoint":                   base + "/token",
			"registration_endpoint":            base + "/register",
			"code_challenge_methods_supported": []string{"S256"},
			"grant_types_supported":            []string{"authorization_code", "refresh_token"},
		})
	case "/register":
		var req struct {
			RedirectURIs []string `json:"redirect_uris"`
		}
		if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&req) != nil || len(req.RedirectURIs) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_client_metadata"})
			return
		}
		o.mu.Lock()
		o.n++
		id := fmt.Sprintf("client-%d", o.n)
		o.clients[id] = req.RedirectURIs
		o.mu.Unlock()
		writeJSON(w, http.StatusCreated, map[string]any{"client_id": id, "redirect_uris": req.RedirectURIs, "token_endpoint_auth_method": "none"})
	case "/token":
		o.token(w, r)
	case ResourcePath:
		header := r.Header.Get("Authorization")
		o.mu.Lock()
		valid := strings.HasPrefix(header, "Bearer ") && o.tokens[strings.TrimPrefix(header, "Bearer ")]
		o.mu.Unlock()
		if valid {
			writeJSON(w, http.StatusOK, map[string]any{"ok": true})
			return
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="test", resource_metadata="`+base+`/.well-known/oauth-protected-resource`+ResourcePath+`", scope="read"`)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid_token"})
	default:
		http.NotFound(w, r)
	}
}

// token exchanges a code, with its PKCE verifier, or a refresh token, for
// an access token, and a refresh token
func (o *OAuth) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		// The client is authenticated with HTTP Basic, or in the form
		client, secret, basic := r.BasicAuth()
		if !basic {
			client, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
		} else if id, err := url.QueryUnescape(client); err == nil {
			client = id
			if s, err := url.QueryUnescape(secret); err == nil {
				secret = s
			}
		}
		g, exists := o.codes[r.PostForm.Get("code")]
		delete(o.codes, r.PostForm.Get("code"))
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		switch {
		case !exists, g.client != client, g.redirect != r.PostForm.Get("redirect_uri"):
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant"})
			return
		case o.secrets[g.client] != secret:
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid_client"})
			return
		case base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge:
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant", "error_description": "code_verifier doesn't match"})
			return
		case r.PostForm.Get("resource") != g.resource:
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_target"})
			return
		}
	case "refresh_token":
		if !o.refreshes[r.PostForm.Get("refresh_token")] {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant"})
			return
		}
		delete(o.refreshes, r.PostForm.Get("refresh_token"))
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unsupported_grant_type"})
		return
	}
	o.n++
	access, refresh := fmt.Sprintf("access-%d", o.n), fmt.Sprintf("refresh-%d", o.n)
	o.tokens[access], o.refreshes[refresh] = true, true
	writeJSON(w, http.StatusOK, map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": 3600, "refresh_token": refresh})
}
