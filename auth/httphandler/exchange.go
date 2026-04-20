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
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	// Packages
	jwt "github.com/golang-jwt/jwt/v5"
	uuid "github.com/google/uuid"
	autherr "github.com/mutablelogic/go-auth"
	auth "github.com/mutablelogic/go-auth/auth/manager"
	provider "github.com/mutablelogic/go-auth/auth/provider"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	types "github.com/mutablelogic/go-server/pkg/types"
	oauth2 "golang.org/x/oauth2"
)

const (
	tokenUseAccess  = "access"
	tokenUseRefresh = "refresh"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type ExchangeRequest struct {
	GrantType string `json:"grant_type" jsonschema:"OAuth 2.0 grant type. Use authorization_code for provider code exchange or refresh_token to refresh an existing local session." example:"authorization_code" required:""`
	schema.AuthorizationCodeRequest
	RefreshTokenExchangeRequest
}

type AuthorizationCodeExchangeRequest struct {
	GrantType string `json:"grant_type" jsonschema:"OAuth 2.0 grant type for exchanging a provider-issued authorization code." enum:"authorization_code" example:"authorization_code" required:""`
	schema.AuthorizationCodeRequest
}

type RefreshTokenGrantRequest struct {
	GrantType string `json:"grant_type" jsonschema:"OAuth 2.0 grant type for refreshing an existing local session." enum:"refresh_token" example:"refresh_token" required:""`
	RefreshTokenExchangeRequest
}

type RefreshTokenExchangeRequest struct {
	Token string `json:"refresh_token,omitempty" jsonschema:"Previously issued local refresh token. Required when grant_type is refresh_token." example:"eyJhbGciOiJSUzI1NiIsImtpZCI6ImxvY2FsLW1haW4ifQ..."`
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (req ExchangeRequest) Validate() error {
	if req.GrantType == "" {
		return httpresponse.Err(http.StatusBadRequest).With("grant_type is required")
	} else if req.GrantType != "authorization_code" && req.GrantType != "refresh_token" {
		return httpresponse.Err(http.StatusBadRequest).Withf("unsupported grant_type %q", req.GrantType)
	}
	// Return success
	return nil
}

func (req RefreshTokenExchangeRequest) Validate() error {
	if req.Token == "" {
		return httpresponse.Err(http.StatusBadRequest).With("refresh_token is required")
	}
	// Return success
	return nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func exchange(ctx context.Context, manager *auth.Manager, w http.ResponseWriter, r *http.Request) error {
	var request ExchangeRequest
	if err := httprequest.Read(r, &request); err != nil {
		return httpresponse.Error(w, autherr.HTTPError(err))
	} else if err := request.Validate(); err != nil {
		return httpresponse.Error(w, autherr.HTTPError(err))
	}

	// Other authorize or refresh
	switch request.GrantType {
	case "authorization_code":
		codeRequest := request.AuthorizationCodeRequest
		if err := codeRequest.Validate(); err != nil {
			return httpresponse.Error(w, autherr.HTTPError(err))
		}

		// Get the identity provider for the request
		identity_provider, err := manager.Provider(codeRequest.Provider)
		if err != nil {
			return httpresponse.Error(w, autherr.HTTPError(err))
		}

		// Exchange the authorization code for an identity
		identity, err := identity_provider.ExchangeAuthorizationCode(ctx, provider.ExchangeRequest{
			Code:         codeRequest.Code,
			RedirectURL:  codeRequest.RedirectURI,
			CodeVerifier: codeRequest.CodeVerifier,
			Nonce:        codeRequest.Nonce,
		})
		if err != nil {
			return httpresponse.Error(w, autherr.HTTPError(err))
		}

		// Now login with this identity
		user, session, err := manager.LoginWithIdentity(ctx, types.Value(identity), codeRequest.Meta)
		if err != nil {
			return httpresponse.Error(w, autherr.HTTPError(err))
		}

		// Sign the token
		config, err := manager.OIDCConfig()
		if err != nil {
			return httpresponse.Error(w, autherr.HTTPError(err))
		}
		accessToken, err := manager.OIDCSign(accessTokenClaims(config.Issuer, user, session))
		if err != nil {
			return httpresponse.Error(w, autherr.HTTPError(err))
		}
		refreshToken, err := manager.OIDCSign(refreshTokenClaims(config.Issuer, user, session))
		if err != nil {
			return httpresponse.Error(w, autherr.HTTPError(err))
		}

		return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), oauth2.Token{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			TokenType:    "Bearer",
			Expiry:       session.ExpiresAt,
			ExpiresIn:    tokenExpiresIn(session.ExpiresAt),
		})
	case "refresh_token":
		refreshRequest := request.RefreshTokenExchangeRequest
		if err := refreshRequest.Validate(); err != nil {
			return httpresponse.Error(w, autherr.HTTPError(err))
		}

		// Get the claims from the refresh token
		config, err := manager.OIDCConfig()
		if err != nil {
			return httpresponse.Error(w, autherr.HTTPError(err))
		}
		claims, err := manager.OIDCVerify(refreshRequest.Token, config.Issuer)
		if err != nil {
			return httpresponse.Error(w, autherr.HTTPError(err))
		}

		// Refresh the session and return a new access & refresh token
		sessionValue, err := stringClaim(claims, "sid")
		if err != nil {
			return httpresponse.Error(w, autherr.HTTPError(err))
		}
		sessionID, err := schema.SessionIDFromString(sessionValue)
		if err != nil {
			return httpresponse.Error(w, autherr.HTTPError(err))
		}
		if use, err := stringClaim(claims, "token_use"); err != nil {
			return httpresponse.Error(w, autherr.HTTPError(err))
		} else if use != tokenUseRefresh {
			return httpresponse.Error(w, autherr.HTTPError(autherr.ErrBadParameter.With("refresh_token must be a refresh token")))
		}
		refreshCounter, err := uint64Claim(claims, "refresh_counter")
		if err != nil {
			return httpresponse.Error(w, autherr.HTTPError(err))
		}
		user, session, err := manager.RefreshSession(ctx, sessionID, refreshCounter)
		if err != nil {
			return httpresponse.Error(w, autherr.HTTPError(err))
		}
		accessToken, err := manager.OIDCSign(accessTokenClaims(config.Issuer, user, session))
		if err != nil {
			return httpresponse.Error(w, autherr.HTTPError(err))
		}
		refreshToken, err := manager.OIDCSign(refreshTokenClaims(config.Issuer, user, session))
		if err != nil {
			return httpresponse.Error(w, autherr.HTTPError(err))
		}
		return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), oauth2.Token{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			TokenType:    "Bearer",
			Expiry:       session.ExpiresAt,
			ExpiresIn:    tokenExpiresIn(session.ExpiresAt),
		})
	default:
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).Withf("unsupported grant_type %q", request.GrantType))
	}

}

func tokenExpiresIn(expiry time.Time) int64 {
	remaining := time.Until(expiry.UTC())
	if remaining <= 0 {
		return 0
	}
	return int64(remaining / time.Second)
}

func accessTokenClaims(issuer string, user *schema.User, session *schema.Session) jwt.MapClaims {
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss":       issuer,
		"aud":       issuer,
		"sub":       uuid.UUID(user.ID).String(),
		"sid":       uuid.UUID(session.ID).String(),
		"iat":       now.Unix(),
		"nbf":       now.Unix(),
		"exp":       session.ExpiresAt.UTC().Unix(),
		"token_use": tokenUseAccess,
		"user":      user,
		"session":   session,
	}
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

func refreshTokenClaims(issuer string, user *schema.User, session *schema.Session) jwt.MapClaims {
	now := time.Now().UTC()
	return jwt.MapClaims{
		"iss":             issuer,
		"aud":             issuer,
		"sub":             uuid.UUID(user.ID).String(),
		"sid":             uuid.UUID(session.ID).String(),
		"iat":             now.Unix(),
		"nbf":             now.Unix(),
		"exp":             session.RefreshExpiresAt.UTC().Unix(),
		"token_use":       tokenUseRefresh,
		"refresh_counter": session.RefreshCounter,
	}
}

func stringClaim(claims map[string]any, key string) (string, error) {
	value, ok := claims[key]
	if !ok {
		return "", autherr.ErrBadParameter.Withf("token missing %s claim", key)
	}
	text, ok := value.(string)
	if !ok || text == "" {
		return "", autherr.ErrBadParameter.Withf("token %s claim is invalid", key)
	}
	return text, nil
}

func uint64Claim(claims map[string]any, key string) (uint64, error) {
	value, ok := claims[key]
	if !ok {
		return 0, autherr.ErrBadParameter.Withf("token missing %s claim", key)
	}
	switch value := value.(type) {
	case uint64:
		return value, nil
	case int:
		if value < 0 {
			break
		}
		return uint64(value), nil
	case int64:
		if value < 0 {
			break
		}
		return uint64(value), nil
	case float64:
		if value < 0 || value != float64(uint64(value)) {
			break
		}
		return uint64(value), nil
	case json.Number:
		parsed, err := value.Int64()
		if err == nil && parsed >= 0 {
			return uint64(parsed), nil
		}
	}
	return 0, autherr.ErrBadParameter.Withf("token %s claim is invalid: %v", key, fmt.Sprintf("%T", value))
}
