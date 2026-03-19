package httphandler

import (
	"context"
	"net/http"

	// Packages
	manager "github.com/djthorpe/go-auth/pkg/manager"
	schema "github.com/djthorpe/go-auth/schema"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
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
			Get: &openapi.Operation{
				Tags:        []string{"User"},
				Summary:     "List users",
				Description: "Returns a filtered list of users.",
				Parameters: []openapi.Parameter{
					{
						Name:        "email",
						In:          openapi.ParameterInQuery,
						Description: "Filter users by canonical email address.",
						Schema:      jsonschema.MustFor[string](),
					},
					{
						Name:        "status",
						In:          openapi.ParameterInQuery,
						Description: "Filter users by one or more lifecycle states.",
						Schema:      jsonschema.MustFor[[]schema.UserStatus](),
					},
					{
						Name:        "offset",
						In:          openapi.ParameterInQuery,
						Description: "Pagination offset.",
						Schema:      jsonschema.MustFor[uint64](),
					},
					{
						Name:        "limit",
						In:          openapi.ParameterInQuery,
						Description: "Maximum number of users to return.",
						Schema:      jsonschema.MustFor[uint64](),
					},
				},
				Responses: map[string]openapi.Response{
					"200": {
						Description: "User list.",
						Content: map[string]openapi.MediaType{
							"application/json": {
								Schema: userListSchema(),
							},
						},
					},
					"400": {
						Description: "Invalid filter or pagination parameters.",
					},
				},
			},
			Post: &openapi.Operation{
				Tags:        []string{"User"},
				Summary:     "Create user",
				Description: "Creates a new local user.",
				RequestBody: &openapi.RequestBody{
					Description: "User fields for the new account.",
					Required:    true,
					Content: map[string]openapi.MediaType{
						"application/json": {
							Schema: jsonschema.MustFor[schema.UserMeta](),
						},
					},
				},
				Responses: map[string]openapi.Response{
					"201": {
						Description: "Created user.",
						Content: map[string]openapi.MediaType{
							"application/json": {
								Schema: userSchema(),
							},
						},
					},
					"400": {
						Description: "Invalid request body or user creation failure.",
					},
				},
			},
		}
}

// Return an http.HandlerFunc for the user endpoint
func UserItemHandler(mgr *manager.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	userIDSchema := uuidSchema()

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
			Get: &openapi.Operation{
				Tags:        []string{"User"},
				Summary:     "Get user",
				Description: "Returns a single user by ID.",
				Parameters: []openapi.Parameter{
					{
						Name:        "user",
						In:          openapi.ParameterInPath,
						Description: "User ID.",
						Required:    true,
						Schema:      userIDSchema,
					},
				},
				Responses: map[string]openapi.Response{
					"200": {
						Description: "Requested user.",
						Content: map[string]openapi.MediaType{
							"application/json": {
								Schema: userSchema(),
							},
						},
					},
					"400": {
						Description: "Invalid user ID.",
					},
					"404": {
						Description: "User not found.",
					},
				},
			},
			Patch: &openapi.Operation{
				Tags:        []string{"User"},
				Summary:     "Update user",
				Description: "Updates mutable fields on a user.",
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
					Description: "User fields to update.",
					Required:    true,
					Content: map[string]openapi.MediaType{
						"application/json": {
							Schema: jsonschema.MustFor[schema.UserMeta](),
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
						Description: "Invalid user ID or request body.",
					},
					"404": {
						Description: "User not found.",
					},
				},
			},
			Delete: &openapi.Operation{
				Tags:        []string{"User"},
				Summary:     "Delete user",
				Description: "Deletes a user by ID.",
				Parameters: []openapi.Parameter{
					{
						Name:        "user",
						In:          openapi.ParameterInPath,
						Description: "User ID.",
						Required:    true,
						Schema:      userIDSchema,
					},
				},
				Responses: map[string]openapi.Response{
					"204": {
						Description: "User deleted.",
					},
					"400": {
						Description: "Invalid user ID.",
					},
					"404": {
						Description: "User not found.",
					},
				},
			},
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
