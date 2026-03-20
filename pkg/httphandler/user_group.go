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
func UserGroupHandler(mgr *manager.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return "user/{user}/group", func(w http.ResponseWriter, r *http.Request) {
		// Convert user to uuid
		user, err := schema.UserIDFromString(r.PathValue("user"))
		if err != nil {
			_ = httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
			return
		}

		switch r.Method {
		case http.MethodPost:
			_ = addUserGroup(r.Context(), mgr, w, r, user)
		case http.MethodDelete:
			_ = removeUserGroup(r.Context(), mgr, w, r, user)
		default:
			_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
		}
	}, nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func addUserGroup(ctx context.Context, mgr *manager.Manager, w http.ResponseWriter, r *http.Request, user schema.UserID) error {
	var req schema.UserGroupList
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}

	response, err := mgr.AddUserGroups(ctx, user, []string(req))
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}

	// Return the user
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), response)
}

func removeUserGroup(ctx context.Context, mgr *manager.Manager, w http.ResponseWriter, r *http.Request, user schema.UserID) error {
	var req schema.UserGroupList
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}

	response, err := mgr.RemoveUserGroups(ctx, user, []string(req))
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}

	// Return the user
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), response)
}
