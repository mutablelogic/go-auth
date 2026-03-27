package auth

import (
	"net/http"

	// Packages
	manager "github.com/djthorpe/go-auth/pkg/manager"
	middleware "github.com/djthorpe/go-auth/pkg/middleware"
	"github.com/djthorpe/go-auth/pkg/oidc"
	schema "github.com/djthorpe/go-auth/schema"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	openapi "github.com/mutablelogic/go-server/pkg/openapi/schema"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func UserInfoHandler(manager *manager.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return oidc.UserInfoPath, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_ = getUserInfo(w, r)
		default:
			_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
		}
	}, &openapi.PathItem{Summary: "Authenticated user info", Description: "Returns the client-facing identity claims for the authenticated local token."}
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func getUserInfo(w http.ResponseWriter, r *http.Request) error {
	user, ok := middleware.UserFromContext(r.Context())
	if !ok || user == nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusInternalServerError).With("authenticated user missing from context"))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), schema.NewUserInfo(user))
}
