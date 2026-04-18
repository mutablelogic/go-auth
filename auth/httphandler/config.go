package httphandler

import (
	"net/http"

	// Packages
	autherr "github.com/mutablelogic/go-auth"
	manager "github.com/mutablelogic/go-auth/auth/manager"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
	opts "github.com/mutablelogic/go-server/pkg/openapi"
)

///////////////////////////////////////////////////////////////////////////////
// HANDLER METHODS

func ConfigHandler(manager *manager.Manager, doc *opts.MarkdownDoc) (string, *jsonschema.Schema, httprequest.PathItem) {
	return "config", nil, httprequest.NewPathItem(
		"Public provider configuration",
		"Returns the upstream provider details that are safe to expose to clients that need to start an authentication flow.",
		"Auth",
	).Get(
		func(w http.ResponseWriter, r *http.Request) {
			config, err := manager.AuthConfig()
			if err != nil {
				_ = httpresponse.Error(w, autherr.HTTPError(err))
				return
			}
			_ = httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), config)
		},
		"Get public auth configuration",
		opts.WithDescription(doc.Section(3, "GET /auth/config").Body),
		opts.WithJSONResponse(http.StatusOK, jsonschema.MustFor[schema.PublicClientConfigurations]()),
		opts.WithErrorResponse(http.StatusNotFound, "No upstream providers are configured."),
	)
}
