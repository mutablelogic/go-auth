package httphandler

import (
	"errors"
	"net/http"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	autherr "github.com/mutablelogic/go-auth"
	manager "github.com/mutablelogic/go-auth/auth/manager"
	middleware "github.com/mutablelogic/go-auth/auth/middleware"
	oidc "github.com/mutablelogic/go-auth/auth/oidc"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	httprouter "github.com/mutablelogic/go-server/pkg/httprouter"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
)

///////////////////////////////////////////////////////////////////////////////
// INTERFACES

type HTTPRouter interface {
	RegisterPath(path string, params *jsonschema.Schema, pathitem httprequest.PathItem) error
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// RegisterAuthHandlers registers auth handlers with the provided router.
func RegisterAuthHandlers(manager *manager.Manager) func(*httprouter.Router) error {
	return func(router *httprouter.Router) error {
		authenticated := middleware.AuthN(manager)
		return errors.Join(
			router.RegisterPath(ConfigHandler(manager)),
			router.RegisterPath(OIDCConfigHandler(manager)),
			router.RegisterPath(JWKSHandler(manager)),
			router.RegisterPath(ProtectedResourceHandler(manager)),
			router.RegisterPath(UserInfoHandler(manager, authenticated)),
			router.RegisterPath(AuthorizationHandler(manager)),
			router.RegisterPath(ExchangeHandler(manager)),
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

///////////////////////////////////////////////////////////////////////////////
// HANDLER METHODS

func ConfigHandler(manager *manager.Manager) (string, *jsonschema.Schema, httprequest.PathItem) {
	return "config", nil, httprequest.NewPathItem(
		"Configuration Endpoint",
		"Returns the identity provider configuration details.",
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
		"Configuration endpoint",
	)
}

func AuthorizationHandler(manager *manager.Manager) (string, *jsonschema.Schema, httprequest.PathItem) {
	return oidc.AuthorizationPath, nil, httprequest.NewPathItem(
		"OpenID Authorization Endpoint",
		"Starts a local browser-based authorization flow, or redirects to a configured upstream provider when an explicit provider is requested.",
		"Auth",
	).Get(
		func(w http.ResponseWriter, r *http.Request) {
			_ = authorize(r.Context(), manager, w, r)
		},
		"Authorization endpoint",
	)
}

func ExchangeHandler(manager *manager.Manager) (string, *jsonschema.Schema, httprequest.PathItem) {
	return oidc.AuthCodePath, nil, httprequest.NewPathItem(
		"Authorization code exchange",
		"Exchanges a registered-provider authorization code and returns a signed local token plus userinfo.",
		"Auth",
	).Post(
		func(w http.ResponseWriter, r *http.Request) {
			_ = exchange(r.Context(), manager, w, r)
		},
		"Exchange authorization code",
	)
}

func OIDCConfigHandler(manager *manager.Manager) (string, *jsonschema.Schema, httprequest.PathItem) {
	return oidc.ConfigPath, nil, httprequest.NewPathItem(
		"OpenID Connect Configuration",
		"Returns the OpenID Connect configuration for this server.",
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
	)
}

func UserInfoHandler(manager *manager.Manager, auth func(http.HandlerFunc) http.HandlerFunc) (string, *jsonschema.Schema, httprequest.PathItem) {
	return oidc.UserInfoPath, nil, httprequest.NewPathItem(
		"Authenticated User Information",
		"Returns the client-facing identity claims for the authenticated local token.",
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
	)
}

func JWKSHandler(manager *manager.Manager) (string, *jsonschema.Schema, httprequest.PathItem) {
	return oidc.JWKSPath, nil, httprequest.NewPathItem(
		"JSON Web Key Set",
		"Returns the public signing keys for this server.",
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
	)
}

func ProtectedResourceHandler(manager *manager.Manager) (string, *jsonschema.Schema, httprequest.PathItem) {
	return oidc.ProtectedResourcePath, nil, httprequest.NewPathItem(
		"OAuth Protected Resource Metadata",
		"Returns OAuth protected-resource metadata for this server.",
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
	)
}
