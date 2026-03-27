package manager

import (
	"context"
	"net/http"

	// Packages
	coremanager "github.com/djthorpe/go-auth/pkg/manager"
	schema "github.com/djthorpe/go-auth/schema"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
	openapi "github.com/mutablelogic/go-server/pkg/openapi/schema"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// ScopeHandler returns an http.HandlerFunc for the scope endpoint.
func ScopeHandler(mgr *coremanager.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return "scope", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				_ = listScope(r.Context(), mgr, w, r)
			default:
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
			}
		}, &openapi.PathItem{
			Summary:     "Scope operations",
			Description: "Operations on scopes",
			Get: &openapi.Operation{
				Tags:        []string{"Scope"},
				Summary:     "List scopes",
				Description: "Returns a paginated list of distinct scopes across all groups.",
				Parameters: []openapi.Parameter{
					{Name: "q", In: openapi.ParameterInQuery, Description: "Filter scopes by substring match.", Schema: jsonschema.MustFor[string]()},
					{Name: "offset", In: openapi.ParameterInQuery, Description: "Pagination offset.", Schema: jsonschema.MustFor[uint64]()},
					{Name: "limit", In: openapi.ParameterInQuery, Description: "Maximum number of scopes to return.", Schema: jsonschema.MustFor[uint64]()},
				},
				Responses: map[string]openapi.Response{
					"200": {Description: "Scope list.", Content: map[string]openapi.MediaType{"application/json": {Schema: scopeListSchema()}}},
					"400": {Description: "Invalid filter or pagination parameters."},
				},
			},
		}
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func listScope(ctx context.Context, mgr *coremanager.Manager, w http.ResponseWriter, r *http.Request) error {
	var req schema.ScopeListRequest
	if err := httprequest.Query(r.URL.Query(), &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}
	scopes, err := mgr.ListScopes(ctx, req)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), scopes)
}
