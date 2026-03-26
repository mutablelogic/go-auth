package manager

import (
	"net/http"

	// Packages
	manager "github.com/djthorpe/go-auth/pkg/manager"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	openapi "github.com/mutablelogic/go-server/pkg/openapi/schema"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func ConfigHandler(manager *manager.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return "config", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			config, err := manager.AuthConfig()
			if err != nil {
				httpresponse.Error(w, httpErr(err))
			} else {
				httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), config)
			}
		default:
			_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
		}
	}, &openapi.PathItem{Summary: "Public configuration", Description: "Returns the upstream authentication provider details that are safe to expose to clients."}
}
