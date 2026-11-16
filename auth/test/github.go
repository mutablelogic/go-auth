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
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	// Packages
	provider "github.com/mutablelogic/go-auth/auth/provider"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// GitHub is a fake GitHub, at its URL, with its API at APIURL, which gives
// a token for a code, and the user, email addresses and organisations it's
// for, from the API
type GitHub struct {
	*httptest.Server

	codes  *codes[GitHubUser]
	mu     sync.Mutex
	tokens map[string]GitHubUser
}

// GitHubUser is a user of the fake GitHub
type GitHubUser struct {
	ID     int64
	Login  string
	Name   string
	Email  string // public, which can be empty
	Emails []GitHubEmail
	Orgs   []string
}

// GitHubEmail is one of a user's email addresses
type GitHubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// NewGitHub returns a fake GitHub, which is closed when the test ends
func NewGitHub(t testing.TB) *GitHub {
	t.Helper()
	g := &GitHub{codes: newCodes[GitHubUser](), tokens: make(map[string]GitHubUser)}
	mux := http.NewServeMux()

	// GitHub refuses a code with 200, and an error
	mux.HandleFunc("POST /login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		user, ok := g.codes.take(r.Form.Get("code"), r.Form.Get("code_verifier"))
		if !ok {
			writeJSON(w, http.StatusOK, map[string]string{"error": "bad_verification_code", "error_description": "The code passed is incorrect or expired."})
			return
		}
		token := provider.NewVerifier()
		g.mu.Lock()
		g.tokens[token] = user
		g.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]string{"access_token": token, "token_type": "bearer", "scope": r.Form.Get("scope")})
	})
	mux.HandleFunc("GET /api/user", g.api(func(w http.ResponseWriter, user GitHubUser) {
		writeJSON(w, http.StatusOK, map[string]any{"id": user.ID, "login": user.Login, "name": user.Name, "email": user.Email})
	}))
	mux.HandleFunc("GET /api/user/emails", g.api(func(w http.ResponseWriter, user GitHubUser) {
		emails := user.Emails
		if emails == nil {
			emails = []GitHubEmail{}
		}
		writeJSON(w, http.StatusOK, emails)
	}))
	mux.HandleFunc("GET /api/user/orgs", g.api(func(w http.ResponseWriter, user GitHubUser) {
		orgs := make([]map[string]string, 0, len(user.Orgs))
		for _, org := range user.Orgs {
			orgs = append(orgs, map[string]string{"login": org})
		}
		writeJSON(w, http.StatusOK, orgs)
	}))
	g.Server = httptest.NewServer(mux)
	t.Cleanup(g.Close)
	return g
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// APIURL is the URL of the fake's API
func (g *GitHub) APIURL() string {
	return g.URL + "/api"
}

// Code returns a code for the challenge, whose token is for the user, which
// is exchanged once
func (g *GitHub) Code(challenge string, user GitHubUser) string {
	return g.codes.add(challenge, user)
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// api calls fn with the user of the request's bearer token, or else is 401
func (g *GitHub) api(fn func(http.ResponseWriter, GitHubUser)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		g.mu.Lock()
		user, ok := g.tokens[token]
		g.mu.Unlock()
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"message": "Bad credentials"})
			return
		}
		fn(w, user)
	}
}
