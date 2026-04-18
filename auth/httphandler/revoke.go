package httphandler

import (
	"context"
	"net/http"

	// Packages
	autherr "github.com/mutablelogic/go-auth"
	auth "github.com/mutablelogic/go-auth/auth/manager"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type RevokeRequest struct {
	Token string `json:"token,omitempty" jsonschema:"Previously issued local bearer token to revoke. The token must resolve to a local session." example:"eyJhbGciOiJSUzI1NiIsImtpZCI6ImxvY2FsLW1haW4ifQ..." required:""`
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (req RevokeRequest) Validate() error {
	if req.Token == "" {
		return httpresponse.Err(http.StatusBadRequest).With("token is required")
	}
	// Return success
	return nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func revoke(ctx context.Context, manager *auth.Manager, w http.ResponseWriter, r *http.Request) error {
	// Decode the request
	var req RevokeRequest
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else if err := req.Validate(); err != nil {
		return httpresponse.Error(w, autherr.HTTPError(err))
	}

	// Get the claims from the token
	config, err := manager.OIDCConfig()
	if err != nil {
		return httpresponse.Error(w, autherr.HTTPError(err))
	}
	claims, err := manager.OIDCVerify(req.Token, config.Issuer)
	if err != nil {
		return httpresponse.Error(w, autherr.HTTPError(err))
	}

	// Get the session
	session, err := schema.SessionIDFromString(claims["sid"].(string))
	if err != nil {
		return httpresponse.Error(w, autherr.HTTPError(err))
	}

	// Revoke the session
	if _, err := manager.RevokeSession(ctx, session); err != nil {
		return httpresponse.Error(w, autherr.HTTPError(err))
	}

	// Write "no content" response
	return httpresponse.Empty(w, http.StatusNoContent)
}
