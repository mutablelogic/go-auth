package httphandler

import (
	"context"
	"net/http"

	// Packages
	manager "github.com/djthorpe/go-auth/pkg/manager"
	schema "github.com/djthorpe/go-auth/schema"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	openapi "github.com/mutablelogic/go-server/pkg/openapi/schema"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// Return an http.HandlerFunc for the auth endpoint
func AuthHandler(mgr *manager.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return "/auth/login", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodPost:
				_ = exchangeToken(r.Context(), mgr, w, r)
			default:
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
			}
		}, &openapi.PathItem{
			Summary:     "Auth operations",
			Description: "Operations on authentication",
		}
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func exchangeToken(_ context.Context, _ *manager.Manager, w http.ResponseWriter, r *http.Request) error {
	var req schema.TokenRequest
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else if claims, err := req.Validate(); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else {
		return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), claims)
	}
}
