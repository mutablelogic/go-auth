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

package local

import (
	"embed"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	// Packages
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/mutablelogic/go-server/pkg/httpresponse"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type formData struct {
	Title               string
	Error               string
	Action              string
	Provider            string
	RedirectURL         string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	LoginHint           string
	Scope               string
}

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

//go:embed form.html
var formFS embed.FS

var loginTemplate = template.Must(template.ParseFS(formFS, "form.html"))

///////////////////////////////////////////////////////////////////////////////
// HTTP HANDLERS

func (p *Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		_ = p.serveForm(w, r, "")
	case http.MethodPost:
		_ = p.submitForm(w, r)
	default:
		httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed))
	}
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func (p *Provider) serveForm(w http.ResponseWriter, r *http.Request, formError string) error {
	query := r.URL.Query()
	data := formData{
		Title:               p.title,
		Error:               formError,
		Action:              r.URL.Path,
		Provider:            p.key,
		RedirectURL:         strings.TrimSpace(query.Get("redirect_uri")),
		State:               strings.TrimSpace(query.Get("state")),
		Nonce:               strings.TrimSpace(query.Get("nonce")),
		CodeChallenge:       strings.TrimSpace(query.Get("code_challenge")),
		CodeChallengeMethod: strings.TrimSpace(query.Get("code_challenge_method")),
		LoginHint:           strings.TrimSpace(query.Get("login_hint")),
		Scope:               strings.TrimSpace(query.Get("scope")),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	return loginTemplate.Execute(w, data)
}

func (p *Provider) submitForm(w http.ResponseWriter, r *http.Request) error {
	// Parse the form and validate required fields
	if err := r.ParseForm(); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}
	redirectURL := strings.TrimSpace(r.PostForm.Get("redirect_uri"))
	state := strings.TrimSpace(r.PostForm.Get("state"))
	if redirectURL == "" || state == "" {
		return p.serveForm(w, requestWithFormAsQuery(r), "redirect_uri and state are required")
	}
	email, err := normalizeEmail(r.PostForm.Get("login_hint"))
	if err != nil {
		return p.serveForm(w, requestWithFormAsQuery(r), err.Error())
	}
	issuer, err := p.codec.Issuer()
	if err != nil {
		return httpresponse.Error(w, err)
	}

	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss":          issuer,
		"sub":          email,
		"email":        email,
		"typ":          localAuthorizationCodeType,
		"redirect_uri": redirectURL,
		"iat":          now.Unix(),
		"nbf":          now.Unix(),
		"exp":          now.Add(5 * time.Minute).Unix(),
	}
	if nonce := strings.TrimSpace(r.PostForm.Get("nonce")); nonce != "" {
		claims["nonce"] = nonce
	}
	if challenge := strings.TrimSpace(r.PostForm.Get("code_challenge")); challenge != "" {
		claims["code_challenge"] = challenge
		claims["code_challenge_method"] = strings.TrimSpace(r.PostForm.Get("code_challenge_method"))
	}
	code, err := p.codec.Sign(claims)
	if err != nil {
		return httpresponse.Error(w, err)
	}
	uri, err := url.Parse(redirectURL)
	if err != nil {
		return p.serveForm(w, requestWithFormAsQuery(r), "redirect_uri is invalid")
	}

	// Redirect with code and state as query parameters
	query := uri.Query()
	query.Set("code", code)
	query.Set("state", state)
	if scope := strings.TrimSpace(r.PostForm.Get("scope")); scope != "" {
		query.Set("scope", scope)
	}
	uri.RawQuery = query.Encode()
	http.Redirect(w, r, uri.String(), http.StatusFound)
	return nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func requestWithFormAsQuery(r *http.Request) *http.Request {
	clone := r.Clone(r.Context())
	clone.URL = new(url.URL)
	*clone.URL = *r.URL
	clone.URL.RawQuery = r.PostForm.Encode()
	return clone
}
