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
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
	providerpkg "github.com/djthorpe/go-auth/pkg/provider"
	schema "github.com/djthorpe/go-auth/schema"
	jwt "github.com/golang-jwt/jwt/v5"
	uuid "github.com/google/uuid"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	oauth2 "golang.org/x/oauth2"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

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

func issueOAuthLoginResponse(ctx context.Context, mgr *managerpkg.Manager, w http.ResponseWriter, r *http.Request, claims map[string]any, meta schema.MetaMap) error {
	if identity, err := schema.NewIdentityFromClaims(claims); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else {
		return issueOAuthIdentityResponse(ctx, mgr, w, r, identity, meta)
	}
}

func issueOAuthIdentityResponse(ctx context.Context, mgr *managerpkg.Manager, w http.ResponseWriter, r *http.Request, identity schema.IdentityInsert, meta schema.MetaMap) error {
	if user, session, err := mgr.LoginWithIdentity(ctx, identity, meta); err != nil {
		return httpresponse.Error(w, httpErr(err))
	} else if config, err := mgr.OIDCConfig(r); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusInternalServerError).With(err))
	} else if token, err := mgr.OIDCSign(loginTokenClaims(config.Issuer, user, session)); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusInternalServerError).With(err))
	} else {
		return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), localOAuthTokenResponse(token, session.ExpiresAt))
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
		req := authorizationCodeRequestFromForm(r.PostForm)
		if strings.TrimSpace(req.Provider) == "" {
			req.Provider = schema.OAuthClientKeyLocal
		}
		if err := req.Validate(); err != nil {
			return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
		}
		if provider, err := mgr.Provider(req.Provider); err == nil {
			return exchangeRegisteredAuthorizationCodeGrant(ctx, mgr, provider, w, r, &req)
		} else if req.Provider == schema.OAuthClientKeyLocal {
			return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).Withf("provider %q is not configured", req.Provider))
		}
		return exchangeProviderAuthorizationCodeGrant(ctx, mgr, w, r, &req)
	case "refresh_token":
		return exchangeLocalRefreshTokenGrant(ctx, mgr, w, r)
	default:
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).Withf("unsupported grant_type %q", grantType))
	}
}

func exchangeRegisteredAuthorizationCodeGrant(ctx context.Context, mgr *managerpkg.Manager, provider providerpkg.Provider, w http.ResponseWriter, r *http.Request, req *schema.AuthorizationCodeRequest) error {
	if req == nil {
		parsed := authorizationCodeRequestFromForm(r.PostForm)
		req = &parsed
	}
	if err := req.Validate(); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	}
	if provider == nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With("provider is required"))
	}
	identity, err := provider.ExchangeAuthorizationCode(ctx, providerpkg.ExchangeRequest{
		Code:         req.Code,
		RedirectURL:  req.RedirectURL,
		CodeVerifier: req.CodeVerifier,
		Nonce:        req.Nonce,
	})
	if err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	}
	if identity == nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).Withf("provider %q returned no identity", req.Provider))
	}
	return issueOAuthIdentityResponse(ctx, mgr, w, r, *identity, req.Meta)
}

func exchangeProviderAuthorizationCodeGrant(ctx context.Context, mgr *managerpkg.Manager, w http.ResponseWriter, r *http.Request, req *schema.AuthorizationCodeRequest) error {
	if req == nil {
		parsed := authorizationCodeRequestFromForm(r.PostForm)
		req = &parsed
	}
	if err := req.Validate(); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	}
	claims, err := exchangeAuthorizationCode(ctx, mgr, req)
	if err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	}
	return issueOAuthLoginResponse(ctx, mgr, w, r, claims, req.Meta)
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

func authorizationCodeRequestFromForm(values map[string][]string) schema.AuthorizationCodeRequest {
	req := schema.AuthorizationCodeRequest{
		Provider:     strings.TrimSpace(firstFormValue(values, "provider")),
		Code:         strings.TrimSpace(firstFormValue(values, "code")),
		RedirectURL:  strings.TrimSpace(firstFormValue(values, "redirect_uri")),
		CodeVerifier: strings.TrimSpace(firstFormValue(values, "code_verifier")),
		Nonce:        strings.TrimSpace(firstFormValue(values, "nonce")),
	}
	return req
}

func firstFormValue(values map[string][]string, key string) string {
	if len(values[key]) == 0 {
		return ""
	}
	return values[key][0]
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
