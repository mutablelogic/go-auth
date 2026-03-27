package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	// Packages
	manager "github.com/djthorpe/go-auth/pkg/manager"
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
	providerpkg "github.com/djthorpe/go-auth/pkg/provider"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	openapi "github.com/mutablelogic/go-server/pkg/openapi/schema"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func AuthorizationHandler(mgr *manager.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return oidc.AuthorizationPath, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_ = authorize(r.Context(), mgr, w, r)
		default:
			_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
		}
	}, &openapi.PathItem{Summary: "Authorization endpoint", Description: "Starts a local browser-based authorization flow, or redirects to a configured upstream provider when an explicit provider is requested."}
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func authorize(ctx context.Context, manager *manager.Manager, w http.ResponseWriter, r *http.Request) error {
	params := r.URL.Query()
	providerName := strings.TrimSpace(params.Get("provider"))

	// Redirect URL
	redirectURL := strings.TrimSpace(params.Get("redirect_uri"))
	if redirectURL == "" {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With("redirect_uri is required"))
	}

	// ClientID
	clientID := strings.TrimSpace(params.Get("client_id"))
	if clientID == "" {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With("client_id is required"))
	}

	// ResponseType
	responseType := strings.TrimSpace(params.Get("response_type"))
	if responseType == "" {
		responseType = oidc.ResponseTypeCode
	}
	if responseType != oidc.ResponseTypeCode {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).Withf("unsupported response_type %q", responseType))
	}

	// State
	state := strings.TrimSpace(params.Get("state"))
	if state == "" {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With("state is required"))
	}
	provider, err := authorizationProvider(manager, providerName)
	if err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	}
	return authorizeRegisteredProvider(ctx, manager, provider, w, r, clientID, redirectURL, state)
}

func authorizeRegisteredProvider(ctx context.Context, manager *manager.Manager, provider providerpkg.Provider, w http.ResponseWriter, r *http.Request, clientID, redirectURL, state string) error {
	if provider == nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With("provider is required"))
	}
	providerURL := ""
	if handler, _ := provider.HTTPHandler(); handler != nil {
		var err error
		providerURL, err = manager.ProviderPath(provider.Key())
		if err != nil {
			return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
		}
		providerURL = providerAuthorizationPath(r, providerURL)
	}
	response, err := provider.BeginAuthorization(ctx, providerpkg.AuthorizationRequest{
		ClientID:            clientID,
		RedirectURL:         redirectURL,
		ProviderURL:         providerURL,
		State:               state,
		Scopes:              authorizeScopes(r),
		Nonce:               strings.TrimSpace(r.URL.Query().Get("nonce")),
		CodeChallenge:       strings.TrimSpace(r.URL.Query().Get("code_challenge")),
		CodeChallengeMethod: strings.TrimSpace(r.URL.Query().Get("code_challenge_method")),
		LoginHint:           strings.TrimSpace(r.URL.Query().Get("login_hint")),
	})
	if err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	}
	http.Redirect(w, r, response.RedirectURL, http.StatusFound)
	return nil
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

func authorizationProvider(manager *manager.Manager, requested string) (providerpkg.Provider, error) {
	requested = strings.TrimSpace(requested)
	if requested != "" {
		return manager.Provider(requested)
	}
	public, err := manager.AuthConfig()
	if err != nil {
		return nil, err
	}
	if len(public) == 1 {
		for key := range public {
			return manager.Provider(key)
		}
	}
	if len(public) == 0 {
		return nil, fmt.Errorf("no provider is available for authorization")
	}
	return nil, fmt.Errorf("provider is required when multiple providers are configured")
}
