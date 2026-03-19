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

// Return an http.HandlerFunc for the user endpoint
func UserHandler(mgr *manager.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return "user", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodPost:
				_ = createUser(r.Context(), mgr, w, r)
			default:
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
			}
		}, &openapi.PathItem{
			Summary:     "User operations",
			Description: "Operations on users",
		}
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func createUser(ctx context.Context, mgr *manager.Manager, w http.ResponseWriter, r *http.Request) error {
	var req schema.UserMeta
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}

	user, err := mgr.CreateUser(ctx, req, nil)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}

	// Return the created user
	return httpresponse.JSON(w, http.StatusCreated, httprequest.Indent(r), user)
}
