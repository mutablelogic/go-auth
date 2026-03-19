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
			case http.MethodGet:
				_ = listUser(r.Context(), mgr, w, r)
			default:
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
			}
		}, &openapi.PathItem{
			Summary:     "User operations",
			Description: "Operations on users",
		}
}

// Return an http.HandlerFunc for the user endpoint
func UserItemHandler(mgr *manager.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return "user/{user}", func(w http.ResponseWriter, r *http.Request) {
			// Convert user to uuid
			user, err := schema.UserIDFromString(r.PathValue("user"))
			if err != nil {
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
				return
			}

			switch r.Method {
			case http.MethodGet:
				_ = getUser(r.Context(), mgr, w, r, user)
			case http.MethodPatch:
				_ = updateUser(r.Context(), mgr, w, r, user)
			case http.MethodDelete:
				_ = deleteUser(r.Context(), mgr, w, r, user)
			default:
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
			}
		}, &openapi.PathItem{
			Summary:     "User operations",
			Description: "Operations on a specific user",
		}
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func createUser(ctx context.Context, mgr *manager.Manager, w http.ResponseWriter, r *http.Request) error {
	var req schema.UserMeta
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}

	// Create a user
	user, err := mgr.CreateUser(ctx, req, nil)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}

	// Return the created user
	return httpresponse.JSON(w, http.StatusCreated, httprequest.Indent(r), user)
}

func listUser(ctx context.Context, mgr *manager.Manager, w http.ResponseWriter, r *http.Request) error {
	var req schema.UserListRequest
	if err := httprequest.Query(r.URL.Query(), &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}

	// List users with filtering
	users, err := mgr.ListUsers(ctx, req)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}

	// Return the list of users
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), users)
}

func getUser(ctx context.Context, mgr *manager.Manager, w http.ResponseWriter, r *http.Request, user schema.UserID) error {
	// List users with filtering
	response, err := mgr.GetUser(ctx, user)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}

	// Return the user
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), response)
}

func updateUser(ctx context.Context, mgr *manager.Manager, w http.ResponseWriter, r *http.Request, user schema.UserID) error {
	// Read the request body
	var req schema.UserMeta
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}

	// Update the user
	response, err := mgr.UpdateUser(ctx, user, req)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}

	// Return the user
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), response)
}

func deleteUser(ctx context.Context, mgr *manager.Manager, w http.ResponseWriter, _ *http.Request, user schema.UserID) error {
	// Delete the user
	_, err := mgr.DeleteUser(ctx, user)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}

	// Return no content
	return httpresponse.Empty(w, http.StatusNoContent)
}
