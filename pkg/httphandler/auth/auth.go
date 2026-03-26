package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
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
	types "github.com/mutablelogic/go-server/pkg/types"
	oauth2 "golang.org/x/oauth2"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

const (
	localAuthorizationCodeType  = "authorization_code"
	localAuthorizationCodeEmail = "local@example.com"
)

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

func AuthCodeHandler(mgr *managerpkg.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return "/auth/code", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			_ = exchangeCode(r.Context(), mgr, w, r)
		default:
			_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
		}
	}, &openapi.PathItem{Summary: "Authorization code exchange", Description: "Exchanges either a locally issued OAuth authorization code or an upstream provider authorization code and returns a signed local token plus userinfo."}
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

func exchangeCode(ctx context.Context, mgr *managerpkg.Manager, w http.ResponseWriter, r *http.Request) error {
	if isOAuthTokenRequest(r) {
		return exchangeLocalOAuthToken(ctx, mgr, w, r)
	}
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

func exchangeLocalOAuthToken(ctx context.Context, mgr *managerpkg.Manager, w http.ResponseWriter, r *http.Request) error {
	if err := r.ParseForm(); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	}
	grantType := strings.TrimSpace(r.PostForm.Get("grant_type"))
	switch grantType {
	case "authorization_code":
		return exchangeLocalAuthorizationCodeGrant(ctx, mgr, w, r)
	case "refresh_token":
		return exchangeLocalRefreshTokenGrant(ctx, mgr, w, r)
	default:
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).Withf("unsupported grant_type %q", grantType))
	}
}

func exchangeLocalAuthorizationCodeGrant(ctx context.Context, mgr *managerpkg.Manager, w http.ResponseWriter, r *http.Request) error {
	config, err := mgr.OIDCConfig(r)
	if err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusInternalServerError).With(err))
	}
	clientID := strings.TrimSpace(r.PostForm.Get("client_id"))
	if clientID == "" {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With("client_id is required"))
	}
	redirectURL := strings.TrimSpace(r.PostForm.Get("redirect_uri"))
	if redirectURL == "" {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With("redirect_uri is required"))
	}
	code := strings.TrimSpace(r.PostForm.Get("code"))
	if code == "" {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With("code is required"))
	}
	claims, err := mgr.OIDCVerify(code, config.Issuer)
	if err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	}
	if err := validateLocalAuthorizationCodeClaims(claims, clientID, redirectURL, strings.TrimSpace(r.PostForm.Get("code_verifier"))); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	}
	email, err := localAuthorizationEmailFromClaims(claims)
	if err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	}
	identity := schema.IdentityInsert{
		IdentityKey: schema.IdentityKey{Provider: oidc.OAuthClientKeyLocal, Sub: email},
		IdentityMeta: schema.IdentityMeta{
			Email: email,
			Claims: map[string]any{
				"email": email,
				"name":  localAuthorizationName(email),
			},
		},
	}
	user, session, err := mgr.LoginWithIdentity(ctx, identity, nil)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}
	accessToken, err := mgr.OIDCSign(loginTokenClaims(config.Issuer, user, session))
	if err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusInternalServerError).With(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), localOAuthTokenResponse(accessToken, session.ExpiresAt))
}

func exchangeLocalRefreshTokenGrant(ctx context.Context, mgr *managerpkg.Manager, w http.ResponseWriter, r *http.Request) error {
	config, err := mgr.OIDCConfig(r)
	if err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusInternalServerError).With(err))
	}
	refreshToken := strings.TrimSpace(r.PostForm.Get("refresh_token"))
	if refreshToken == "" {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With("refresh_token is required"))
	}
	claims, err := mgr.OIDCVerify(refreshToken, config.Issuer)
	if err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	}
	sessionID, err := sessionIDFromClaims(claims)
	if err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	}
	user, session, err := mgr.RefreshSession(ctx, sessionID)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}
	accessToken, err := mgr.OIDCSign(loginTokenClaims(config.Issuer, user, session))
	if err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusInternalServerError).With(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), localOAuthTokenResponse(accessToken, session.ExpiresAt))
}

func isOAuthTokenRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	contentType := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))
	return strings.HasPrefix(contentType, "application/x-www-form-urlencoded")
}

func validateLocalAuthorizationCodeClaims(claims map[string]any, clientID, redirectURL, codeVerifier string) error {
	if value, _ := claims["typ"].(string); strings.TrimSpace(value) != localAuthorizationCodeType {
		return fmt.Errorf("invalid local authorization code")
	}
	if audience, _ := claims["aud"].(string); strings.TrimSpace(audience) != clientID {
		return fmt.Errorf("authorization code client_id mismatch")
	}
	if value, _ := claims["redirect_uri"].(string); strings.TrimSpace(value) != redirectURL {
		return fmt.Errorf("authorization code redirect_uri mismatch")
	}
	challenge, _ := claims["code_challenge"].(string)
	challenge = strings.TrimSpace(challenge)
	if challenge == "" {
		return nil
	}
	if codeVerifier == "" {
		return fmt.Errorf("code_verifier is required")
	}
	method, _ := claims["code_challenge_method"].(string)
	switch strings.TrimSpace(method) {
	case "", oidc.CodeChallengeMethodPlain:
		if codeVerifier != challenge {
			return fmt.Errorf("authorization code verifier mismatch")
		}
	case oidc.CodeChallengeMethodS256:
		sum := sha256.Sum256([]byte(codeVerifier))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
			return fmt.Errorf("authorization code verifier mismatch")
		}
	default:
		return fmt.Errorf("unsupported code_challenge_method %q", method)
	}
	return nil
}

func localAuthorizationEmailFromClaims(claims map[string]any) (string, error) {
	email, _ := claims["email"].(string)
	email = strings.TrimSpace(email)
	if email == "" {
		email, _ = claims["sub"].(string)
		email = strings.TrimSpace(email)
	}
	if email == "" {
		return "", fmt.Errorf("authorization code missing email")
	}
	var normalized string
	if !types.IsEmail(email, nil, &normalized) {
		return "", fmt.Errorf("authorization code email is invalid")
	}
	return strings.ToLower(strings.TrimSpace(normalized)), nil
}

func localAuthorizationName(email string) string {
	email = strings.TrimSpace(email)
	if email == "" {
		return "Local User"
	}
	if local, _, ok := strings.Cut(email, "@"); ok && strings.TrimSpace(local) != "" {
		return local
	}
	return "Local User"
}

func localOAuthTokenResponse(token string, expiresAt time.Time) map[string]any {
	expiresIn := int64(time.Until(expiresAt).Seconds())
	if expiresIn < 0 {
		expiresIn = 0
	}
	return map[string]any{
		"access_token":  token,
		"refresh_token": token,
		"token_type":    "Bearer",
		"expires_in":    expiresIn,
	}
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

func getUserInfo(ctx context.Context, _ *managerpkg.Manager, w http.ResponseWriter, r *http.Request) error {
	user, ok := middleware.UserFromContext(ctx)
	if !ok || user == nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusInternalServerError).With("authenticated user missing from context"))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), schema.NewUserInfo(user))
}
