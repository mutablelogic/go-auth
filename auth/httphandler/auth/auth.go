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

package auth

import (
	"context"
	"net/http"
	"strings"
	"time"

	// Packages
	jwt "github.com/golang-jwt/jwt/v5"
	uuid "github.com/google/uuid"
	managerpkg "github.com/mutablelogic/go-auth/auth/manager"
	oidc "github.com/mutablelogic/go-auth/auth/oidc"
	providerpkg "github.com/mutablelogic/go-auth/auth/provider"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
)

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

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

func issueTokenFormIdentityResponse(ctx context.Context, mgr *managerpkg.Manager, w http.ResponseWriter, r *http.Request, identity schema.IdentityInsert, meta schema.MetaMap) error {
	if user, session, err := mgr.LoginWithIdentity(ctx, identity, meta); err != nil {
		return httpresponse.Error(w, httpErr(err))
	} else if config, err := mgr.OIDCConfig(r); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusInternalServerError).With(err))
	} else if token, err := mgr.OIDCSign(loginTokenClaims(config.Issuer, user, session)); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusInternalServerError).With(err))
	} else {
		return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), tokenFormResponse(token, session.ExpiresAt))
	}
}

func exchangeTokenFormRequest(ctx context.Context, mgr *managerpkg.Manager, w http.ResponseWriter, r *http.Request) error {
	if err := r.ParseForm(); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	}
	grantType := strings.TrimSpace(r.PostForm.Get("grant_type"))
	switch grantType {
	case "authorization_code":
		req := authorizationCodeRequestFromForm(r.PostForm)
		if err := req.Validate(); err != nil {
			return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
		}
		provider, err := mgr.Provider(req.Provider)
		if err != nil {
			return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
		}
		return exchangeRegisteredAuthorizationCodeGrant(ctx, mgr, provider, w, r, &req)
	case "refresh_token":
		return exchangeRefreshTokenGrant(ctx, mgr, w, r)
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
	return issueTokenFormIdentityResponse(ctx, mgr, w, r, *identity, req.Meta)
}

func exchangeRefreshTokenGrant(ctx context.Context, mgr *managerpkg.Manager, w http.ResponseWriter, r *http.Request) error {
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
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), tokenFormResponse(accessToken, session.ExpiresAt))
}

func isFormEncodedTokenRequest(r *http.Request) bool {
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

func tokenFormResponse(token string, expiresAt time.Time) map[string]any {
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
	claims := jwt.MapClaims{"iss": issuer, "aud": issuer, "sub": uuid.UUID(user.ID).String(), "sid": uuid.UUID(session.ID).String(), "iat": now.Unix(), "nbf": now.Unix(), "exp": session.ExpiresAt.UTC().Unix(), "user": user, "session": session}
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
