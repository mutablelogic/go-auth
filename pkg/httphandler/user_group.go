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
	userIDSchema := uuidSchema()

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
		}, &openapi.PathItem{
			Summary:     "User group membership operations",
			Description: "Batch add or remove group memberships for a specific user",
			Post: &openapi.Operation{
				Tags:        []string{"User"},
				Summary:     "Add user groups",
				Description: "Adds one or more groups to a user and returns the updated user.",
				Parameters: []openapi.Parameter{
					{
						Name:        "user",
						In:          openapi.ParameterInPath,
						Description: "User ID.",
						Required:    true,
						Schema:      userIDSchema,
					},
				},
				RequestBody: &openapi.RequestBody{
					Description: "Array of group identifiers to add to the user.",
					Required:    true,
					Content: map[string]openapi.MediaType{
						"application/json": {
							Schema: userGroupListSchema(),
						},
					},
				},
				Responses: map[string]openapi.Response{
					"200": {
						Description: "Updated user.",
						Content: map[string]openapi.MediaType{
							"application/json": {
								Schema: userSchema(),
							},
						},
					},
					"400": {
						Description: "Invalid user ID, request body, or group identifiers.",
					},
					"404": {
						Description: "User or group not found.",
					},
				},
			},
			Delete: &openapi.Operation{
				Tags:        []string{"User"},
				Summary:     "Remove user groups",
				Description: "Removes one or more groups from a user and returns the updated user.",
				Parameters: []openapi.Parameter{
					{
						Name:        "user",
						In:          openapi.ParameterInPath,
						Description: "User ID.",
						Required:    true,
						Schema:      userIDSchema,
					},
				},
				RequestBody: &openapi.RequestBody{
					Description: "Array of group identifiers to remove from the user.",
					Required:    true,
					Content: map[string]openapi.MediaType{
						"application/json": {
							Schema: userGroupListSchema(),
						},
					},
				},
				Responses: map[string]openapi.Response{
					"200": {
						Description: "Updated user.",
						Content: map[string]openapi.MediaType{
							"application/json": {
								Schema: userSchema(),
							},
						},
					},
					"400": {
						Description: "Invalid user ID, request body, or group identifiers.",
					},
					"404": {
						Description: "User or group not found.",
					},
				},
			},
		}
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
