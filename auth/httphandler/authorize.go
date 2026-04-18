package httphandler

import (
	"context"
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
	Provider string `json:"provider,omitempty"`
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

	// Get the provider
	identity_provider, err := authorizationProvider(manager, strings.TrimSpace(req.Provider))
	if err != nil {
		return httpresponse.Error(w, auth.HTTPError(err))
	}

	// Get the HTTP handler URL for the provider
	if url, err := manager.ProviderPath(identity_provider.Key()); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else {
		req.ProviderURL = providerAuthorizationPath(r, url)
	}

	// Begin the authorization flow with the provider
	response, err := identity_provider.BeginAuthorization(ctx, req.AuthorizationRequest)
	if err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	}

	// Redirect the user to the provider's authorization URL
	http.Redirect(w, r, response.RedirectURL, http.StatusFound)

	// Return success
	return nil
}

func authorizationProvider(manager *manager.Manager, key string) (provider.Provider, error) {
	config, err := manager.AuthConfig()
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

func providerAuthorizationPath(r *http.Request, providerPath string) string {
	providerPath = strings.TrimSpace(providerPath)
	if providerPath == "" {
		return "/"
	}
	basePath := "/"
	if r != nil && r.URL != nil {
		currentPath := strings.TrimSpace(r.URL.Path)
		if strings.HasSuffix(currentPath, oidc.AuthorizationPath) {
			basePath = strings.TrimSuffix(currentPath, oidc.AuthorizationPath)
		}
	}
	uri, err := url.JoinPath(basePath, providerPath)
	if err != nil {
		return "/" + strings.TrimLeft(providerPath, "/")
	}
	return uri
}
