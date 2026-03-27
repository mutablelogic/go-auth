package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	// Packages
	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	manager "github.com/djthorpe/go-auth/pkg/manager"
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
	providerpkg "github.com/djthorpe/go-auth/pkg/provider"
	schema "github.com/djthorpe/go-auth/schema"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	openapi "github.com/mutablelogic/go-server/pkg/openapi/schema"
	oauth2 "golang.org/x/oauth2"
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
	if providerName == "" {
		if provider, err := manager.Provider(schema.OAuthClientKeyLocal); err == nil {
			return authorizeRegisteredProvider(ctx, manager, provider, w, r, clientID, redirectURL, state)
		}
	} else if provider, err := manager.Provider(providerName); err == nil {
		return authorizeRegisteredProvider(ctx, manager, provider, w, r, clientID, redirectURL, state)
	} else if providerName == schema.OAuthClientKeyLocal {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).Withf("provider %q is not configured", providerName))
	}

	// Get the provider configuration
	_, config, err := authorizeProviderConfig(manager, providerName)
	if err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	}

	// Construct the provider's authorization URL
	provider, err := coreoidc.NewProvider(ctx, config.Issuer)
	if err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	}

	// Create the OAuth2 config for this provider for the authorization code flow
	oauthConfig := &oauth2.Config{ClientID: config.ClientID, ClientSecret: config.ClientSecret, RedirectURL: redirectURL, Endpoint: provider.Endpoint(), Scopes: authorizeScopes(r)}
	options := make([]oauth2.AuthCodeOption, 0, 3)
	if nonce := strings.TrimSpace(params.Get("nonce")); nonce != "" {
		options = append(options, oauth2.SetAuthURLParam("nonce", nonce))
	}
	if challenge := strings.TrimSpace(params.Get("code_challenge")); challenge != "" {
		options = append(options, oauth2.SetAuthURLParam("code_challenge", challenge))
	}
	if method := strings.TrimSpace(params.Get("code_challenge_method")); method != "" {
		options = append(options, oauth2.SetAuthURLParam("code_challenge_method", method))
	}

	// Redirect to the upstream provider's authorization URL
	http.Redirect(w, r, oauthConfig.AuthCodeURL(state, options...), http.StatusFound)
	return nil
}

func authorizeRegisteredProvider(ctx context.Context, manager *manager.Manager, provider providerpkg.Provider, w http.ResponseWriter, r *http.Request, clientID, redirectURL, state string) error {
	if provider == nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With("provider is required"))
	}
	handler, _ := provider.HTTPHandler()
	if handler == nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).Withf("provider %q has no browser authorization handler", provider.Key()))
	}
	providerURL, err := manager.ProviderPath(provider.Key())
	if err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	}
	providerURL = providerAuthorizationPath(r, providerURL)
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

func authorizeProviderConfig(manager *manager.Manager, provider string) (string, schema.ClientConfiguration, error) {
	provider = strings.TrimSpace(provider)
	if provider != "" {
		config, err := manager.OAuthClientConfig(provider)
		if err != nil {
			return "", schema.ClientConfiguration{}, err
		}
		if strings.TrimSpace(config.ClientID) == "" {
			return "", schema.ClientConfiguration{}, fmt.Errorf("provider %q has no client_id", provider)
		}
		return provider, config, nil
	}
	public, err := manager.AuthConfig()
	if err != nil {
		return "", schema.ClientConfiguration{}, err
	}
	selected := ""
	for key, cfg := range public {
		if key == schema.OAuthClientKeyLocal || strings.TrimSpace(cfg.ClientID) == "" {
			continue
		}
		if selected != "" {
			return "", schema.ClientConfiguration{}, fmt.Errorf("provider is required when multiple upstream providers are configured")
		}
		selected = key
	}
	if selected == "" {
		return "", schema.ClientConfiguration{}, fmt.Errorf("no upstream provider is available for authorization")
	}
	config, err := manager.OAuthClientConfig(selected)
	if err != nil {
		return "", schema.ClientConfiguration{}, err
	}
	return selected, config, nil
}
