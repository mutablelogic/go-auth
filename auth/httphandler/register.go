// Copyright 2026 David Thorpe
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package httphandler

import (
	_ "embed"
	"errors"
	"net/http"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	manager "github.com/mutablelogic/go-auth/auth/manager"
	middleware "github.com/mutablelogic/go-auth/auth/middleware"
	oidc "github.com/mutablelogic/go-auth/auth/oidc"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	httprouter "github.com/mutablelogic/go-server/pkg/httprouter"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
	opts "github.com/mutablelogic/go-server/pkg/openapi"
	oauth2 "golang.org/x/oauth2"
)

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

//go:embed AUTHN.md
var AuthDoc []byte

//go:embed AUTHZ.md
var ManagerDoc []byte

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// RegisterAuthHandlers registers auth handlers with the provided router.
func RegisterAuthHandlers(manager *manager.Manager) func(*httprouter.Router) error {
	return func(router *httprouter.Router) error {
		// Parse the markdown documentation
		doc := opts.ParseMarkdown(AuthDoc)

		// Add top-level and tag descriptions to the spec
		router.Spec().Info.Description = doc.Section(1, "Auth & Identity Provider Handlers").Body

		// Register the tag group
		router.Spec().AddTagGroup("Authentication", "Auth", "Identity Provider")
		router.Spec().AddTag("Auth", doc.Section(2, "Auth").Body)
		router.Spec().AddTag("Identity Provider", doc.Section(2, "Identity Provider").Body)

		// Register the bearer token security scheme
		if err := router.RegisterSecurityScheme(schema.SecurityBearerAuth, middleware.NewBearerAuth(manager)); err != nil {
			return err
		}

		// Create an authenticated handler wrapper
		authenticated := middleware.AuthN(manager)

		// Register the paths
		return errors.Join(
			router.RegisterPath(ConfigHandler(manager, doc)),
			router.RegisterPath(OIDCConfigHandler(manager, doc)),
			router.RegisterPath(JWKSHandler(manager, doc)),
			router.RegisterPath(ProtectedResourceHandler(manager, doc)),
			router.RegisterPath(UserInfoHandler(manager, authenticated, doc)),
			router.RegisterPath(AuthorizationHandler(manager, doc)),
			router.RegisterPath(ExchangeHandler(manager, doc)),
			router.RegisterPath(RevokeHandler(manager, doc)),
		)
	}
}

// RegisterProviderHandlers registers provider-specific handlers with the provided router.
func RegisterProviderHandlers(manager *manager.Manager) func(*httprouter.Router) error {
	return func(router *httprouter.Router) error {
		var result error
		for _, key := range manager.ProviderKeys() {
			if identity_provider, err := manager.Provider(key); err != nil {
				result = errors.Join(result, auth.ErrInternalServerError.Withf("error getting provider %q: %v", key, err))
			} else if handler := identity_provider.HTTPHandler(); handler == nil {
				continue
			} else if path, err := manager.ProviderPath(key); err != nil {
				result = errors.Join(result, auth.ErrInternalServerError.Withf("error getting path for provider %q: %v", key, err))
			} else {
				result = errors.Join(result, router.RegisterPath(path, nil, handler))
			}
		}
		return result
	}
}

// RegisterManagerHandlers registers provider-specific handlers with the provided router.
func RegisterManagerHandlers(manager *manager.Manager) func(*httprouter.Router) error {
	return func(router *httprouter.Router) error {
		// Parse the markdown documentation
		doc := opts.ParseMarkdown(AuthDoc)

		// Add top-level and tag descriptions to the spec
		router.Spec().Info.Description = doc.Section(1, "Auth & Identity Provider Handlers").Body

		// Register the tag group
		router.Spec().AddTagGroup("Authorization", "Scope")

		// Create an authenticated handler wrapper
		authenticated := middleware.AuthN(manager)

		// Register the paths
		return errors.Join(
			router.RegisterPath(ScopeHandler(manager, authenticated, doc)),
		)
	}
}

func AuthorizationHandler(manager *manager.Manager, doc *opts.MarkdownDoc) (string, *jsonschema.Schema, httprequest.PathItem) {
	return oidc.AuthorizationPath, nil, httprequest.NewPathItem(
		"OpenID Authorization Endpoint",
		"Selects a provider-specific browser authorization flow and redirects the client to the resulting local or upstream provider URL.",
		"Auth",
	).Get(
		func(w http.ResponseWriter, r *http.Request) {
			_ = authorize(r.Context(), manager, w, r)
		},
		"Authorization endpoint",
		opts.WithDescription(doc.Section(3, "GET /auth/authorize").Body),
		opts.WithQuery(jsonschema.MustFor[AuthRequest]()),
		opts.WithNoContentResponse(http.StatusFound, "Redirects the browser to the local or upstream provider authorization URL."),
		opts.WithErrorResponse(http.StatusBadRequest, "Missing or invalid query parameters, unsupported PKCE configuration, or an invalid provider selection."),
		opts.WithErrorResponse(http.StatusNotFound, "No identity providers are configured."),
	)
}

func ExchangeHandler(manager *manager.Manager, doc *opts.MarkdownDoc) (string, *jsonschema.Schema, httprequest.PathItem) {
	return oidc.AuthCodePath, nil, httprequest.NewPathItem(
		"Authorization code exchange",
		"Handles authorization_code and refresh_token grants and returns locally signed bearer tokens in an OAuth token response.",
		"Auth",
	).Post(
		func(w http.ResponseWriter, r *http.Request) {
			_ = exchange(r.Context(), manager, w, r)
		},
		"Exchange authorization code",
		opts.WithDescription(doc.Section(3, "POST /auth/code").Body),
		opts.WithNamedJSONRequest(
			"ExchangeRequest",
			opts.NamedSchema("AuthorizationCodeExchangeRequest", jsonschema.MustFor[AuthorizationCodeExchangeRequest]()),
			opts.NamedSchema("RefreshTokenGrantRequest", jsonschema.MustFor[RefreshTokenGrantRequest]()),
		),
		opts.WithNamedFormRequest(
			"ExchangeRequest",
			opts.NamedSchema("AuthorizationCodeExchangeRequest", jsonschema.MustFor[AuthorizationCodeExchangeRequest]()),
			opts.NamedSchema("RefreshTokenGrantRequest", jsonschema.MustFor[RefreshTokenGrantRequest]()),
		),
		opts.WithJSONResponse(http.StatusOK, jsonschema.MustFor[oauth2.Token]()),
		opts.WithErrorResponse(http.StatusBadRequest, "Missing or invalid grant_type, exchange parameters, authorization code, or refresh token."),
		opts.WithErrorResponse(http.StatusInternalServerError, "The server could not issue a local token after a successful exchange."),
	)
}

func OIDCConfigHandler(manager *manager.Manager, doc *opts.MarkdownDoc) (string, *jsonschema.Schema, httprequest.PathItem) {
	return oidc.ConfigPath, nil, httprequest.NewPathItem(
		"OpenID Connect Configuration",
		"Returns the OpenID Connect discovery document for locally issued tokens and supported OAuth features.",
		"Auth",
	).Get(
		func(w http.ResponseWriter, r *http.Request) {
			config, err := manager.OIDCConfig()
			if err != nil {
				_ = httpresponse.Error(w, httpresponse.ErrInternalError.With(err))
				return
			}
			_ = httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), config)
		},
		"Get OIDC configuration",
		opts.WithDescription(doc.Section(3, "GET /.well-known/openid-configuration").Body),
		opts.WithJSONResponse(http.StatusOK, jsonschema.MustFor[oidc.OIDCConfiguration]()),
		opts.WithErrorResponse(http.StatusInternalServerError, "The server could not build the local OpenID Connect discovery document."),
	)
}

func UserInfoHandler(manager *manager.Manager, auth func(http.HandlerFunc) http.HandlerFunc, doc *opts.MarkdownDoc) (string, *jsonschema.Schema, httprequest.PathItem) {
	return oidc.UserInfoPath, nil, httprequest.NewPathItem(
		"Authenticated User Information",
		"Returns the client-facing identity claims for the authenticated bearer token issued by this server.",
		"Auth",
	).Get(
		auth(func(w http.ResponseWriter, r *http.Request) {
			user := middleware.UserFromContext(r.Context())
			if user == nil {
				_ = httpresponse.Error(w, httpresponse.ErrNotAuthorized)
				return
			}
			_ = httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), schema.NewUserInfo(user))

		}),
		"Get authenticated user info",
		opts.WithDescription(doc.Section(3, "GET /auth/userinfo").Body),
		opts.WithSecurity(schema.SecurityBearerAuth),
		opts.WithJSONResponse(http.StatusOK, jsonschema.MustFor[schema.UserInfo]()),
		opts.WithErrorResponse(http.StatusUnauthorized, "A valid local bearer token is required to access the userinfo endpoint."),
	)
}

func JWKSHandler(manager *manager.Manager, doc *opts.MarkdownDoc) (string, *jsonschema.Schema, httprequest.PathItem) {
	return oidc.JWKSPath, nil, httprequest.NewPathItem(
		"JSON Web Key Set",
		"Returns the public JSON Web Key Set used to verify bearer tokens issued by this server.",
		"Auth",
	).Get(
		func(w http.ResponseWriter, r *http.Request) {
			jwks, err := manager.OIDCJWKSet()
			if err != nil {
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusInternalServerError).With(err))
				return
			}
			_ = httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), jwks)
		},
		"Get JSON Web Key Set",
		opts.WithDescription(doc.Section(3, "GET /.well-known/jwks.json").Body),
		opts.WithJSONResponse(http.StatusOK, jsonschema.MustFor[oidc.JSONWebKeySet]()),
		opts.WithErrorResponse(http.StatusInternalServerError, "The server could not build the local JSON Web Key Set."),
	)
}

func ProtectedResourceHandler(manager *manager.Manager, doc *opts.MarkdownDoc) (string, *jsonschema.Schema, httprequest.PathItem) {
	return oidc.ProtectedResourcePath, nil, httprequest.NewPathItem(
		"OAuth Protected Resource Metadata",
		"Returns OAuth protected-resource metadata describing this server as a bearer-token resource.",
		"Auth",
	).Get(
		func(w http.ResponseWriter, r *http.Request) {
			config, err := manager.ProtectedResourceMetadata(r)
			if err != nil {
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusInternalServerError).With(err))
				return
			}
			_ = httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), config)

		},
		"Get OAuth protected resource metadata",
		opts.WithDescription(doc.Section(3, "GET /.well-known/oauth-protected-resource").Body),
		opts.WithJSONResponse(http.StatusOK, jsonschema.MustFor[oidc.ProtectedResourceMetadata]()),
		opts.WithErrorResponse(http.StatusInternalServerError, "The server could not build the protected-resource metadata document."),
	)
}
