package manager

import (
	"context"
	"net/http"

	// Packages
	manager "github.com/djthorpe/go-auth/pkg/manager"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	openapi "github.com/mutablelogic/go-server/pkg/openapi/schema"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func ConfigHandler(mgr *manager.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return "config", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_ = getAuthConfig(r.Context(), mgr, w, r)
		default:
			_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
		}
	}, &openapi.PathItem{Summary: "Public configuration", Description: "Returns the upstream authentication provider details that are safe to expose to clients."}
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func getAuthConfig(_ context.Context, mgr *manager.Manager, w http.ResponseWriter, r *http.Request) error {
	config, err := mgr.AuthConfig()
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), config)
}
