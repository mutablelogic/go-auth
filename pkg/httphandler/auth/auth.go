package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	// Packages
	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	managerpkg "github.com/djthorpe/go-auth/pkg/manager"
	middleware "github.com/djthorpe/go-auth/pkg/middleware"
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
	schema "github.com/djthorpe/go-auth/schema"
	jwt "github.com/golang-jwt/jwt/v5"
	uuid "github.com/google/uuid"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
	openapi "github.com/mutablelogic/go-server/pkg/openapi/schema"
	oauth2 "golang.org/x/oauth2"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func AuthHandler(mgr *managerpkg.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return "/auth/login", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodPost:
				_ = exchangeToken(r.Context(), mgr, w, r)
			default:
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
			}
		}, &openapi.PathItem{
			Summary:     "Auth operations",
			Description: "Exchange a verified provider token for the corresponding local user.",
			Post: &openapi.Operation{
				Tags:        []string{"Auth"},
				Summary:     "Exchange identity token",
				Description: "Validates the upstream identity token, resolves the matching identity, and returns a signed local token plus userinfo.",
				RequestBody: &openapi.RequestBody{Description: "Provider token and metadata used for authentication.", Required: true, Content: map[string]openapi.MediaType{"application/json": {Schema: jsonschema.MustFor[schema.TokenRequest]()}}},
				Responses:   map[string]openapi.Response{"200": {Description: "Signed local session token and userinfo.", Content: map[string]openapi.MediaType{"application/json": {Schema: tokenResponseSchema()}}}, "400": {Description: "Invalid request body, unsupported provider, or token verification failure."}, "409": {Description: "The verified identity conflicts with an existing account."}},
			},
		}
}

func AuthCredentialsHandler(mgr *managerpkg.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return "/auth/credentials", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			_ = loginWithCredentials(r.Context(), mgr, w, r)
		default:
			_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
		}
	}, &openapi.PathItem{Summary: "Local credentials login", Description: "Creates or resolves a local testing identity using only an email address and returns a signed local token plus userinfo."}
}

func AuthCodeHandler(mgr *managerpkg.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return "/auth/code", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			_ = exchangeCode(r.Context(), mgr, w, r)
		default:
			_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
		}
	}, &openapi.PathItem{Summary: "Authorization code exchange", Description: "Exchanges an OAuth authorization code using the server-side client secret, resolves the upstream identity, and returns a signed local token plus userinfo."}
}

func AuthConfigHandler(mgr *managerpkg.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return "/auth/config", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_ = getAuthConfig(r.Context(), mgr, w, r)
		default:
			_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
		}
	}, &openapi.PathItem{Summary: "Public auth configuration", Description: "Returns the upstream authentication provider details that are safe to expose to clients."}
}

func AuthorizationHandler(mgr *managerpkg.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return "/" + oidc.AuthorizationPath, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_ = authorize(r.Context(), mgr, w, r)
		default:
			_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
		}
	}, &openapi.PathItem{Summary: "Authorization endpoint", Description: "Starts a browser-based authorization flow using the configured upstream provider."}
}

func RefreshHandler(mgr *managerpkg.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return "/auth/refresh", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			_ = refreshToken(r.Context(), mgr, w, r)
		default:
			_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
		}
	}, &openapi.PathItem{Summary: "Session refresh", Description: "Refresh a previously issued local session token when the current session remains eligible."}
}

func RevokeHandler(mgr *managerpkg.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return "/auth/revoke", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			_ = revokeToken(r.Context(), mgr, w, r)
		default:
			_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
		}
	}, &openapi.PathItem{Summary: "Session revocation", Description: "Revoke a previously issued local session token so the underlying session can no longer be refreshed or accepted by session-aware checks."}
}

func UserInfoHandler(mgr *managerpkg.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return "/auth/userinfo", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_ = getUserInfo(r.Context(), mgr, w, r)
		default:
			_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
		}
	}, &openapi.PathItem{Summary: "Authenticated user info", Description: "Returns the client-facing identity claims for the authenticated local token."}
}

func ConfigHandler(mgr *managerpkg.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return oidc.ConfigPath, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_ = getOIDCConfig(r.Context(), mgr, w, r)
		default:
			_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
		}
	}, &openapi.PathItem{Summary: "OpenID discovery document", Description: "Returns the OpenID Connect configuration for this server."}
}

func JWKSHandler(mgr *managerpkg.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return oidc.JWKSPath, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_ = getJWKS(r.Context(), mgr, w, r)
		default:
			_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
		}
	}, &openapi.PathItem{Summary: "JSON Web Key Set", Description: "Returns the public signing keys for this server."}
}

func ProtectedResourceHandler(mgr *managerpkg.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return oidc.ProtectedResourcePath, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_ = getProtectedResourceMetadata(r.Context(), mgr, w, r)
		default:
			_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
		}
	}, &openapi.PathItem{Summary: "OAuth protected resource metadata", Description: "Returns OAuth protected-resource metadata for this server."}
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func exchangeToken(ctx context.Context, mgr *managerpkg.Manager, w http.ResponseWriter, r *http.Request) error {
	var req schema.TokenRequest
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else if claims, err := req.Validate(ctx); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else {
		return issueLoginResponse(ctx, mgr, w, r, claims, req.Meta)
	}
}

func authorize(ctx context.Context, mgr *managerpkg.Manager, w http.ResponseWriter, r *http.Request) error {
	_, config, err := authorizeProviderConfig(mgr, strings.TrimSpace(r.URL.Query().Get("provider")))
	if err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	}
	redirectURL := strings.TrimSpace(r.URL.Query().Get("redirect_uri"))
	if redirectURL == "" {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With("redirect_uri is required"))
	}
	clientID := strings.TrimSpace(r.URL.Query().Get("client_id"))
	if clientID == "" {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With("client_id is required"))
	}
	responseType := strings.TrimSpace(r.URL.Query().Get("response_type"))
	if responseType == "" {
		responseType = oidc.ResponseTypeCode
	}
	if responseType != oidc.ResponseTypeCode {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).Withf("unsupported response_type %q", responseType))
	}
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	if state == "" {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With("state is required"))
	}
	provider, err := coreoidc.NewProvider(ctx, config.Issuer)
	if err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	}
	oauthConfig := &oauth2.Config{ClientID: config.ClientID, ClientSecret: config.ClientSecret, RedirectURL: redirectURL, Endpoint: provider.Endpoint(), Scopes: authorizeScopes(r)}
	options := make([]oauth2.AuthCodeOption, 0, 3)
	if nonce := strings.TrimSpace(r.URL.Query().Get("nonce")); nonce != "" {
		options = append(options, oauth2.SetAuthURLParam("nonce", nonce))
	}
	if challenge := strings.TrimSpace(r.URL.Query().Get("code_challenge")); challenge != "" {
		options = append(options, oauth2.SetAuthURLParam("code_challenge", challenge))
	}
	if method := strings.TrimSpace(r.URL.Query().Get("code_challenge_method")); method != "" {
		options = append(options, oauth2.SetAuthURLParam("code_challenge_method", method))
	}
	http.Redirect(w, r, oauthConfig.AuthCodeURL(state, options...), http.StatusFound)
	return nil
}

func exchangeCode(ctx context.Context, mgr *managerpkg.Manager, w http.ResponseWriter, r *http.Request) error {
	var req schema.AuthorizationCodeRequest
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else if err := req.Validate(); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else if claims, err := exchangeAuthorizationCode(ctx, mgr, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else {
		return issueLoginResponse(ctx, mgr, w, r, claims, req.Meta)
	}
}

func loginWithCredentials(ctx context.Context, mgr *managerpkg.Manager, w http.ResponseWriter, r *http.Request) error {
	var req schema.CredentialsRequest
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else if err := req.Validate(); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	}
	identity := schema.IdentityInsert{IdentityKey: schema.IdentityKey{Provider: oidc.OAuthClientKeyLocal, Sub: req.Email}, IdentityMeta: schema.IdentityMeta{Email: req.Email, Claims: map[string]any{"email": req.Email}}}
	return issueIdentityLoginResponse(ctx, mgr, w, r, identity, req.Meta)
}

func refreshToken(ctx context.Context, mgr *managerpkg.Manager, w http.ResponseWriter, r *http.Request) error {
	var req schema.RefreshRequest
	token := ""
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else if token = strings.TrimSpace(req.Token); token == "" {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With("token is required"))
	} else if config, err := mgr.OIDCConfig(r); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusInternalServerError).With(err))
	} else if claims, err := mgr.OIDCVerify(token, config.Issuer); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else if session, err := sessionIDFromClaims(claims); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else if user, refreshed, err := mgr.RefreshSession(ctx, session); err != nil {
		return httpresponse.Error(w, httpErr(err))
	} else if token, err := mgr.OIDCSign(loginTokenClaims(config.Issuer, user, refreshed)); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusInternalServerError).With(err))
	} else {
		return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), schema.TokenResponse{Token: token})
	}
}

func revokeToken(ctx context.Context, mgr *managerpkg.Manager, w http.ResponseWriter, r *http.Request) error {
	var req schema.RefreshRequest
	token := ""
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else if token = strings.TrimSpace(req.Token); token == "" {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With("token is required"))
	} else if config, err := mgr.OIDCConfig(r); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusInternalServerError).With(err))
	} else if claims, err := mgr.OIDCVerify(token, config.Issuer); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else if session, err := sessionIDFromClaims(claims); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else if _, err := mgr.RevokeSession(ctx, session); err != nil {
		return httpresponse.Error(w, httpErr(err))
	} else {
		w.WriteHeader(http.StatusNoContent)
		return nil
	}
}

func issueLoginResponse(ctx context.Context, mgr *managerpkg.Manager, w http.ResponseWriter, r *http.Request, claims map[string]any, meta schema.MetaMap) error {
	if identity, err := schema.NewIdentityFromClaims(claims); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else {
		return issueIdentityLoginResponse(ctx, mgr, w, r, identity, meta)
	}
}

func issueIdentityLoginResponse(ctx context.Context, mgr *managerpkg.Manager, w http.ResponseWriter, r *http.Request, identity schema.IdentityInsert, meta schema.MetaMap) error {
	if user, session, err := mgr.LoginWithIdentity(ctx, identity, meta); err != nil {
		return httpresponse.Error(w, httpErr(err))
	} else if config, err := mgr.OIDCConfig(r); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusInternalServerError).With(err))
	} else if token, err := mgr.OIDCSign(loginTokenClaims(config.Issuer, user, session)); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusInternalServerError).With(err))
	} else {
		return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), schema.TokenResponse{Token: token, UserInfo: schema.NewUserInfo(user)})
	}
}

func exchangeAuthorizationCode(ctx context.Context, mgr *managerpkg.Manager, req *schema.AuthorizationCodeRequest) (map[string]any, error) {
	config, err := mgr.OAuthClientConfig(req.Provider)
	if err != nil {
		return nil, err
	}
	provider, err := coreoidc.NewProvider(ctx, config.Issuer)
	if err != nil {
		return nil, err
	}
	oauthConfig := &oauth2.Config{ClientID: config.ClientID, ClientSecret: config.ClientSecret, RedirectURL: req.RedirectURL, Endpoint: provider.Endpoint()}
	options := make([]oauth2.AuthCodeOption, 0, 1)
	if verifier := strings.TrimSpace(req.CodeVerifier); verifier != "" {
		options = append(options, oauth2.SetAuthURLParam("code_verifier", verifier))
	}
	token, err := oauthConfig.Exchange(ctx, req.Code, options...)
	if err != nil {
		return nil, err
	}
	rawIDToken, _ := token.Extra("id_token").(string)
	rawIDToken = strings.TrimSpace(rawIDToken)
	if rawIDToken == "" {
		return nil, fmt.Errorf("upstream token response missing id_token")
	}
	verified, err := provider.Verifier(&coreoidc.Config{ClientID: config.ClientID}).Verify(ctx, rawIDToken)
	if err != nil {
		return nil, err
	}
	claims := make(map[string]any)
	if err := verified.Claims(&claims); err != nil {
		return nil, err
	}
	if err := validateAuthorizationCodeNonce(req.Nonce, claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func validateAuthorizationCodeNonce(expected string, claims map[string]any) error {
	expected = strings.TrimSpace(expected)
	if expected == "" {
		return nil
	}
	actual, _ := claims["nonce"].(string)
	if strings.TrimSpace(actual) != expected {
		return fmt.Errorf("token nonce mismatch")
	}
	return nil
}

func authorizeProviderConfig(mgr *managerpkg.Manager, provider string) (string, oidc.ClientConfiguration, error) {
	provider = strings.TrimSpace(provider)
	if provider != "" {
		config, err := mgr.OAuthClientConfig(provider)
		if err != nil {
			return "", oidc.ClientConfiguration{}, err
		}
		if strings.TrimSpace(config.ClientID) == "" {
			return "", oidc.ClientConfiguration{}, fmt.Errorf("provider %q has no client_id", provider)
		}
		return provider, config, nil
	}
	public, err := mgr.AuthConfig()
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
	config, err := mgr.OAuthClientConfig(selected)
	if err != nil {
		return "", oidc.ClientConfiguration{}, err
	}
	return selected, config, nil
}

func authorizeScopes(r *http.Request) []string {
	if r == nil {
		return []string{oidc.ScopeOpenID, oidc.ScopeEmail, oidc.ScopeProfile}
	}
	scopes := strings.Fields(strings.TrimSpace(r.URL.Query().Get("scope")))
	if len(scopes) == 0 {
		return []string{oidc.ScopeOpenID, oidc.ScopeEmail, oidc.ScopeProfile}
	}
	return scopes
}

func loginTokenClaims(issuer string, user *schema.User, session *schema.Session) jwt.MapClaims {
	now := time.Now().UTC()
	claims := jwt.MapClaims{"iss": issuer, "sub": uuid.UUID(user.ID).String(), "sid": uuid.UUID(session.ID).String(), "iat": now.Unix(), "nbf": now.Unix(), "exp": session.ExpiresAt.UTC().Unix(), "user": user, "session": session}
	if user.Email != "" {
		claims["email"] = user.Email
	}
	if user.Name != "" {
		claims["name"] = user.Name
	}
	if len(user.Groups) > 0 {
		claims["groups"] = user.Groups
	}
	if len(user.Scopes) > 0 {
		claims["scopes"] = user.Scopes
	}
	return claims
}

func sessionIDFromClaims(claims map[string]any) (schema.SessionID, error) {
	value, ok := claims["sid"].(string)
	if !ok || strings.TrimSpace(value) == "" {
		return schema.SessionID{}, httpresponse.Err(http.StatusBadRequest).With("token missing sid claim")
	}
	return schema.SessionIDFromString(value)
}

func getOIDCConfig(_ context.Context, mgr *managerpkg.Manager, w http.ResponseWriter, r *http.Request) error {
	config, err := mgr.OIDCConfig(r)
	if err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusInternalServerError).With(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), config)
}

func getProtectedResourceMetadata(_ context.Context, mgr *managerpkg.Manager, w http.ResponseWriter, r *http.Request) error {
	config, err := mgr.ProtectedResourceMetadata(r)
	if err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusInternalServerError).With(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), config)
}

func getAuthConfig(_ context.Context, mgr *managerpkg.Manager, w http.ResponseWriter, r *http.Request) error {
	config, err := mgr.AuthConfig()
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), config)
}

func getJWKS(_ context.Context, mgr *managerpkg.Manager, w http.ResponseWriter, r *http.Request) error {
	jwks, err := mgr.OIDCJWKSet()
	if err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusInternalServerError).With(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), jwks)
}

func getUserInfo(ctx context.Context, _ *managerpkg.Manager, w http.ResponseWriter, r *http.Request) error {
	user, ok := middleware.UserFromContext(ctx)
	if !ok || user == nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusInternalServerError).With("authenticated user missing from context"))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), schema.NewUserInfo(user))
}
