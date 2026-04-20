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
	"errors"
	"net/http"
	"net/url"
	"strings"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	manager "github.com/mutablelogic/go-auth/auth/manager"
	oidc "github.com/mutablelogic/go-auth/auth/oidc"
	provider "github.com/mutablelogic/go-auth/auth/provider"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type AuthRequest struct {
	Provider string `json:"provider,omitempty" jsonschema:"Optional provider key. Required only when multiple providers are configured and the client must choose one explicitly." example:"google"`
	provider.AuthorizationRequest
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (req *AuthRequest) Validate() error {
	// Validate the parameters, set defaults, and return any errors
	if req.RedirectURL == "" {
		return httpresponse.Err(http.StatusBadRequest).With("redirect_uri is required")
	}
	if req.State == "" {
		return httpresponse.Err(http.StatusBadRequest).With("state is required")
	}
	if req.CodeChallenge == "" {
		return httpresponse.Err(http.StatusBadRequest).With("code_challenge is required")
	}
	if req.CodeChallengeMethod == "" {
		req.CodeChallengeMethod = oidc.CodeChallengeMethodS256
	}
	if req.CodeChallengeMethod != oidc.CodeChallengeMethodS256 && req.CodeChallengeMethod != oidc.CodeChallengeMethodPlain {
		return httpresponse.Err(http.StatusBadRequest).Withf("unsupported code_challenge_method %q", req.CodeChallengeMethod)
	}

	// Return success
	return nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func authorize(ctx context.Context, manager *manager.Manager, w http.ResponseWriter, r *http.Request) error {
	// Decode the request
	var req AuthRequest
	if err := httprequest.Query(r.URL.Query(), &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else if err := req.Validate(); err != nil {
		return httpresponse.Error(w, auth.HTTPError(err))
	}

	// Get the identity provider for the request
	identity_provider, err := authorizationProvider(ctx, manager, req.Provider)
	if err != nil {
		return authorizeError(w, r, req, err)
	}

	// Get the HTTP handler URL for the provider
	if url, err := manager.ProviderPath(identity_provider.Key()); err != nil {
		return authorizeError(w, r, req, err)
	} else {
		req.ProviderURL = providerAuthorizationPath(r, url)
	}

	// Begin the authorization flow with the provider
	response, err := identity_provider.BeginAuthorization(ctx, req.AuthorizationRequest)
	if err != nil {
		return authorizeError(w, r, req, err)
	}

	// Redirect the user to the provider's authorization URL
	http.Redirect(w, r, response.RedirectURL, http.StatusFound)
	return nil
}

func authorizationProvider(ctx context.Context, manager *manager.Manager, key string) (provider.Provider, error) {
	config, err := manager.AuthConfig(ctx)
	if err != nil {
		return nil, err
	} else if len(config) == 0 {
		return nil, auth.ErrInvalidProvider.With("no providers are configured")
	}

	// Return the first provider if no key is specified and only one provider is configured
	if key == "" && len(config) == 1 {
		for key := range config {
			return manager.Provider(key)
		}
	}

	// Return a named provider if the key is specified and exists
	if key != "" {
		return manager.Provider(key)
	}

	// Return an error if multiple providers are configured and no key is specified
	return nil, auth.ErrInvalidProvider.With("provider is required when multiple providers are configured")
}

func authorizeError(w http.ResponseWriter, r *http.Request, req AuthRequest, err error) error {
	redirectURL := strings.TrimSpace(req.RedirectURL)
	state := strings.TrimSpace(req.State)
	if redirectURL == "" || state == "" {
		return httpresponse.Error(w, auth.HTTPError(err))
	}
	uri, parseErr := url.Parse(redirectURL)
	if parseErr != nil || uri.Scheme == "" || uri.Host == "" {
		return httpresponse.Error(w, auth.HTTPError(err))
	}
	values := uri.Query()
	values.Set("error", authorizeErrorCode(err))
	values.Set("error_description", authorizeErrorDescription(err))
	values.Set("state", state)
	uri.RawQuery = values.Encode()
	http.Redirect(w, r, uri.String(), http.StatusFound)
	return nil
}

func authorizeErrorCode(err error) string {
	if err == nil {
		return "server_error"
	}
	var authErr auth.Err
	if errors.As(err, &authErr) {
		switch authErr {
		case auth.ErrBadParameter, auth.ErrInvalidProvider:
			return "invalid_request"
		case auth.ErrForbidden:
			return "access_denied"
		case auth.ErrNotFound, auth.ErrServiceUnavailable, auth.ErrInternalServerError, auth.ErrNotImplemented, auth.ErrConflict:
			return "server_error"
		}
	}
	return "server_error"
}

func authorizeErrorDescription(err error) string {
	if err == nil {
		return "authorization request failed"
	}
	var authErr auth.Err
	if errors.As(err, &authErr) {
		return strings.TrimPrefix(err.Error(), authErr.Error()+": ")
	}
	return err.Error()
}

func providerAuthorizationPath(r *http.Request, providerPath string) string {
	providerPath = strings.TrimSpace(providerPath)
	if providerPath == "" {
		return "/"
	}
	currentPath := "/"
	if r != nil && r.URL != nil {
		currentPath = strings.TrimSpace(r.URL.Path)
	}
	basePath := strings.TrimSuffix(currentPath, oidc.AuthorizationPath)
	if basePath == "" || basePath == currentPath {
		basePath = "/"
	}
	uri, err := url.JoinPath(basePath, providerPath)
	if err != nil {
		return "/" + strings.TrimLeft(providerPath, "/")
	}
	return uri
}
