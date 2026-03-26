package auth

import (
	"context"
	"net/http"

	// Packages

	managerpkg "github.com/djthorpe/go-auth/pkg/manager"
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
	schema "github.com/djthorpe/go-auth/schema"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	openapi "github.com/mutablelogic/go-server/pkg/openapi/schema"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func AuthCodeHandler(mgr *managerpkg.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return oidc.AuthCodePath, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			_ = exchangeCode(r.Context(), mgr, w, r)
		default:
			_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
		}
	}, &openapi.PathItem{Summary: "Authorization code exchange", Description: "Exchanges either a locally issued OAuth authorization code or an upstream provider authorization code and returns a signed local token plus userinfo."}
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

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
