package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	// Packages
	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	manager "github.com/djthorpe/go-auth/pkg/manager"
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
	jwt "github.com/golang-jwt/jwt/v5"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	openapi "github.com/mutablelogic/go-server/pkg/openapi/schema"
	types "github.com/mutablelogic/go-server/pkg/types"
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
	if providerName == "" || providerName == oidc.OAuthClientKeyLocal {
		return authorizeLocal(manager, w, r, clientID, redirectURL, state)
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

func authorizeLocal(manager *manager.Manager, w http.ResponseWriter, r *http.Request, clientID, redirectURL, state string) error {
	code, err := issueLocalAuthorizationCode(manager, r, clientID, redirectURL)
	if err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	}
	uri, err := url.Parse(redirectURL)
	if err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	}
	query := uri.Query()
	query.Set("code", code)
	query.Set("state", state)
	if scope := strings.TrimSpace(r.URL.Query().Get("scope")); scope != "" {
		query.Set("scope", scope)
	}
	uri.RawQuery = query.Encode()
	http.Redirect(w, r, uri.String(), http.StatusFound)
	return nil
}

func issueLocalAuthorizationCode(manager *manager.Manager, r *http.Request, clientID, redirectURL string) (string, error) {
	if manager == nil {
		return "", fmt.Errorf("manager is required")
	}
	issuer, err := manager.OIDCIssuer(r)
	if err != nil {
		return "", err
	}
	email, err := localAuthorizationEmail(r)
	if err != nil {
		return "", err
	}
	claims := jwt.MapClaims{
		"iss":          issuer,
		"sub":          email,
		"aud":          clientID,
		"email":        email,
		"typ":          localAuthorizationCodeType,
		"redirect_uri": redirectURL,
		"iat":          time.Now().UTC().Unix(),
		"nbf":          time.Now().UTC().Unix(),
		"exp":          time.Now().UTC().Add(5 * time.Minute).Unix(),
	}
	if nonce := strings.TrimSpace(r.URL.Query().Get("nonce")); nonce != "" {
		claims["nonce"] = nonce
	}
	if challenge := strings.TrimSpace(r.URL.Query().Get("code_challenge")); challenge != "" {
		claims["code_challenge"] = challenge
		claims["code_challenge_method"] = strings.TrimSpace(r.URL.Query().Get("code_challenge_method"))
	}
	return manager.OIDCSign(claims)
}

func localAuthorizationEmail(r *http.Request) (string, error) {
	if r == nil {
		return localAuthorizationCodeEmail, nil
	}
	candidate := strings.TrimSpace(r.URL.Query().Get("login_hint"))
	if candidate == "" {
		candidate = strings.TrimSpace(r.URL.Query().Get("email"))
	}
	if candidate == "" {
		return localAuthorizationCodeEmail, nil
	}
	var normalized string
	if !types.IsEmail(candidate, nil, &normalized) {
		return "", fmt.Errorf("login_hint must be a valid email address")
	}
	return strings.ToLower(strings.TrimSpace(normalized)), nil
}

func authorizeProviderConfig(manager *manager.Manager, provider string) (string, oidc.ClientConfiguration, error) {
	provider = strings.TrimSpace(provider)
	if provider != "" {
		config, err := manager.OAuthClientConfig(provider)
		if err != nil {
			return "", oidc.ClientConfiguration{}, err
		}
		if strings.TrimSpace(config.ClientID) == "" {
			return "", oidc.ClientConfiguration{}, fmt.Errorf("provider %q has no client_id", provider)
		}
		return provider, config, nil
	}
	public, err := manager.AuthConfig()
	if err != nil {
		return "", oidc.ClientConfiguration{}, err
	}
	selected := ""
	for key, cfg := range public {
		if key == oidc.OAuthClientKeyLocal || strings.TrimSpace(cfg.ClientID) == "" {
			continue
		}
		if selected != "" {
			return "", oidc.ClientConfiguration{}, fmt.Errorf("provider is required when multiple upstream providers are configured")
		}
		selected = key
	}
	if selected == "" {
		return "", oidc.ClientConfiguration{}, fmt.Errorf("no upstream provider is available for authorization")
	}
	config, err := manager.OAuthClientConfig(selected)
	if err != nil {
		return "", oidc.ClientConfiguration{}, err
	}
	return selected, config, nil
}
