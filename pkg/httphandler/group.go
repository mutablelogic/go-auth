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

// Return an http.HandlerFunc for the group endpoint.
func GroupHandler(mgr *manager.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return "group", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodPost:
				_ = createGroup(r.Context(), mgr, w, r)
			case http.MethodGet:
				_ = listGroup(r.Context(), mgr, w, r)
			default:
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
			}
		}, &openapi.PathItem{
			Summary:     "Group operations",
			Description: "Operations on groups",
			Get: &openapi.Operation{
				Tags:        []string{"Group"},
				Summary:     "List groups",
				Description: "Returns a paginated list of groups.",
				Parameters: []openapi.Parameter{
					{
						Name:        "offset",
						In:          openapi.ParameterInQuery,
						Description: "Pagination offset.",
						Schema:      jsonschema.MustFor[uint64](),
					},
					{
						Name:        "limit",
						In:          openapi.ParameterInQuery,
						Description: "Maximum number of groups to return.",
						Schema:      jsonschema.MustFor[uint64](),
					},
				},
				Responses: map[string]openapi.Response{
					"200": {
						Description: "Group list.",
						Content: map[string]openapi.MediaType{
							"application/json": {
								Schema: groupListSchema(),
							},
						},
					},
					"400": {
						Description: "Invalid pagination parameters.",
					},
				},
			},
			Post: &openapi.Operation{
				Tags:        []string{"Group"},
				Summary:     "Create group",
				Description: "Creates a new group.",
				RequestBody: &openapi.RequestBody{
					Description: "Group fields for the new group.",
					Required:    true,
					Content: map[string]openapi.MediaType{
						"application/json": {
							Schema: jsonschema.MustFor[schema.GroupInsert](),
						},
					},
				},
				Responses: map[string]openapi.Response{
					"201": {
						Description: "Created group.",
						Content: map[string]openapi.MediaType{
							"application/json": {
								Schema: groupSchema(),
							},
						},
					},
					"400": {
						Description: "Invalid request body or group creation failure.",
					},
				},
			},
		}
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func createGroup(ctx context.Context, mgr *manager.Manager, w http.ResponseWriter, r *http.Request) error {
	var req schema.GroupInsert
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}

	group, err := mgr.CreateGroup(ctx, req)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}

	return httpresponse.JSON(w, http.StatusCreated, httprequest.Indent(r), group)
}

func listGroup(ctx context.Context, mgr *manager.Manager, w http.ResponseWriter, r *http.Request) error {
	var req schema.GroupListRequest
	if err := httprequest.Query(r.URL.Query(), &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}

	groups, err := mgr.ListGroups(ctx, req)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}

	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), groups)
}
