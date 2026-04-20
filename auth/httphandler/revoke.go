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
	"net/http"

	// Packages
	autherr "github.com/mutablelogic/go-auth"
	auth "github.com/mutablelogic/go-auth/auth/manager"
	manager "github.com/mutablelogic/go-auth/auth/manager"
	oidc "github.com/mutablelogic/go-auth/auth/oidc"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
	opts "github.com/mutablelogic/go-server/pkg/openapi"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type RevokeRequest struct {
	Token string `json:"token,omitempty" jsonschema:"Previously issued local bearer token to revoke. The token must resolve to a local session." example:"eyJhbGciOiJSUzI1NiIsImtpZCI6ImxvY2FsLW1haW4ifQ..." required:""`
}

func (req RevokeRequest) Validate() error {
	if req.Token == "" {
		return httpresponse.Err(http.StatusBadRequest).With("token is required")
	}
	// Return success
	return nil
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func RevokeHandler(manager *manager.Manager, doc *opts.MarkdownDoc) (string, *jsonschema.Schema, httprequest.PathItem) {
	return oidc.AuthRevokePath, nil, httprequest.NewPathItem(
		"Session revocation",
		docBody(doc, 2, "Auth", "Revokes a locally signed session token using either a JSON or form-encoded payload with the same token field."),
		"Auth",
	).Post(
		func(w http.ResponseWriter, r *http.Request) {
			_ = revoke(r.Context(), manager, w, r)
		},
		"Revoke session token",
		opts.WithDescription(doc.Section(3, "POST /auth/revoke").Body),
		opts.WithJSONRequest(opts.NamedSchema("RevokeRequest", jsonschema.MustFor[RevokeRequest]())),
		opts.WithFormRequest(opts.NamedSchema("RevokeRequest", jsonschema.MustFor[RevokeRequest]())),
		opts.WithNoContentResponse(http.StatusNoContent, "The local session token was revoked successfully."),
		opts.WithErrorResponse(http.StatusBadRequest, "Missing or invalid token payload, token format, or session identifier."),
		opts.WithErrorResponse(http.StatusNotFound, "The token resolved to a session that does not exist."),
		opts.WithErrorResponse(http.StatusInternalServerError, "The server could not revoke the local session."),
	)
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
	sessionValue, err := stringClaim(claims, "sid")
	if err != nil {
		return httpresponse.Error(w, autherr.HTTPError(err))
	}
	session, err := schema.SessionIDFromString(sessionValue)
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
