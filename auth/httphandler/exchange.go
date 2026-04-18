package httphandler

import (
	"context"
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

///////////////////////////////////////////////////////////////////////////////
// TYPES

type ExchangeRequest struct {
	GrantType string `json:"grant_type,omitempty"`
}

type RefreshTokenExchangeRequest struct {
	RefreshToken string `json:"refresh_token,omitempty"`
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
	if req.RefreshToken == "" {
		return httpresponse.Err(http.StatusBadRequest).With("refresh_token is required")
	}
	// Return success
	return nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func exchange(ctx context.Context, manager *auth.Manager, w http.ResponseWriter, r *http.Request) error {
	var req ExchangeRequest
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, autherr.HTTPError(err))
	} else if err := req.Validate(); err != nil {
		return httpresponse.Error(w, autherr.HTTPError(err))
	}

	// Other authorize or refresh
	switch req.GrantType {
	case "authorization_code":
		var req schema.AuthorizationCodeRequest
		if err := httprequest.Read(r, &req); err != nil {
			return httpresponse.Error(w, autherr.HTTPError(err))
		} else if err := req.Validate(); err != nil {
			return httpresponse.Error(w, autherr.HTTPError(err))
		}

		// Get the identity provider for the request
		identity_provider, err := manager.Provider(req.Provider)
		if err != nil {
			return httpresponse.Error(w, autherr.HTTPError(err))
		}

		// Exchange the authorization code for an identity
		identity, err := identity_provider.ExchangeAuthorizationCode(ctx, provider.ExchangeRequest{
			Code:         req.Code,
			RedirectURL:  req.RedirectURI,
			CodeVerifier: req.CodeVerifier,
			Nonce:        req.Nonce,
		})
		if err != nil {
			return httpresponse.Error(w, autherr.HTTPError(err))
		}

		// Now login with this identity
		user, session, err := manager.LoginWithIdentity(ctx, types.Value(identity), req.Meta)
		if err != nil {
			return httpresponse.Error(w, autherr.HTTPError(err))
		}

		// Sign the token
		config, err := manager.OIDCConfig()
		if err != nil {
			return httpresponse.Error(w, autherr.HTTPError(err))
		}
		token, err := manager.OIDCSign(tokenClaims(config.Issuer, user, session))
		if err != nil {
			return httpresponse.Error(w, autherr.HTTPError(err))
		}

		return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), oauth2.Token{
			AccessToken:  token,
			RefreshToken: token,
			TokenType:    "Bearer",
			Expiry:       session.ExpiresAt,
			ExpiresIn:    tokenExpiresIn(session.ExpiresAt),
		})
	case "refresh_token":
		var req RefreshTokenExchangeRequest
		if err := httprequest.Read(r, &req); err != nil {
			return httpresponse.Error(w, autherr.HTTPError(err))
		} else if err := req.Validate(); err != nil {
			return httpresponse.Error(w, autherr.HTTPError(err))
		}

		// Get the claims from the refresh token
		config, err := manager.OIDCConfig()
		if err != nil {
			return httpresponse.Error(w, autherr.HTTPError(err))
		}
		claims, err := manager.OIDCVerify(req.RefreshToken, config.Issuer)
		if err != nil {
			return httpresponse.Error(w, autherr.HTTPError(err))
		}

		// Refresh the session and return a new access & refresh token
		sessionID, err := schema.SessionIDFromString(claims["sid"].(string))
		if err != nil {
			return httpresponse.Error(w, autherr.HTTPError(err))
		}
		user, session, err := manager.RefreshSession(ctx, sessionID)
		if err != nil {
			return httpresponse.Error(w, autherr.HTTPError(err))
		}
		token, err := manager.OIDCSign(tokenClaims(config.Issuer, user, session))
		if err != nil {
			return httpresponse.Error(w, autherr.HTTPError(err))
		}
		return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), oauth2.Token{
			AccessToken:  token,
			RefreshToken: token,
			TokenType:    "Bearer",
			Expiry:       session.ExpiresAt,
			ExpiresIn:    tokenExpiresIn(session.ExpiresAt),
		})
	default:
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).Withf("unsupported grant_type %q", req.GrantType))
	}

}

func tokenExpiresIn(expiry time.Time) int64 {
	remaining := time.Until(expiry.UTC())
	if remaining <= 0 {
		return 0
	}
	return int64(remaining / time.Second)
}

func tokenClaims(issuer string, user *schema.User, session *schema.Session) jwt.MapClaims {
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss":     issuer,
		"aud":     issuer,
		"sub":     uuid.UUID(user.ID).String(),
		"sid":     uuid.UUID(session.ID).String(),
		"iat":     now.Unix(),
		"nbf":     now.Unix(),
		"exp":     session.ExpiresAt.UTC().Unix(),
		"user":    user,
		"session": session,
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
