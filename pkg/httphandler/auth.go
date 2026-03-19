package httphandler

import (
	"context"
	"net/http"
	"strings"
	"time"

	// Packages
	manager "github.com/djthorpe/go-auth/pkg/manager"
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
	schema "github.com/djthorpe/go-auth/schema"
	jwt "github.com/golang-jwt/jwt/v5"
	uuid "github.com/google/uuid"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
	openapi "github.com/mutablelogic/go-server/pkg/openapi/schema"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// Return an http.HandlerFunc for the auth endpoint
func AuthHandler(mgr *manager.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return "/auth/login", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodPost:
				_ = exchangeToken(r.Context(), mgr, w, r)
			default:
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
			}
		}, &openapi.PathItem{
			Summary:     "Auth operations",
			Description: "Exchange a verified provider token for the corresponding local user.",
			Post: &openapi.Operation{
				Tags:        []string{"Auth"},
				Summary:     "Exchange identity token",
				Description: "Validates the upstream identity token, resolves the matching identity, and returns the authenticated user.",
				RequestBody: &openapi.RequestBody{
					Description: "Provider token and metadata used for authentication.",
					Required:    true,
					Content: map[string]openapi.MediaType{
						"application/json": {
							Schema: jsonschema.MustFor[schema.TokenRequest](),
						},
					},
				},
				Responses: map[string]openapi.Response{
					"200": {
						Description: "Signed local session token and authenticated user context.",
						Content: map[string]openapi.MediaType{
							"application/json": {
								Schema: jsonschema.MustFor[schema.TokenResponse](),
							},
						},
					},
					"400": {
						Description: "Invalid request body, unsupported provider, or token verification failure.",
					},
				},
			},
		}
}

// Return an http.HandlerFunc for the auth refresh endpoint
func RefreshHandler(mgr *manager.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return "/auth/refresh", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodPost:
				_ = refreshToken(r.Context(), mgr, w, r)
			default:
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
			}
		}, &openapi.PathItem{
			Summary:     "Session refresh",
			Description: "Refresh a previously issued local session token when the current session remains eligible.",
			Post: &openapi.Operation{
				Tags:        []string{"Auth"},
				Summary:     "Refresh session token",
				Description: "Verifies the supplied local session token, refreshes the underlying session, and returns a newly signed local token.",
				RequestBody: &openapi.RequestBody{
					Description: "Previously issued local session token.",
					Required:    true,
					Content: map[string]openapi.MediaType{
						"application/json": {
							Schema: jsonschema.MustFor[schema.RefreshRequest](),
						},
					},
				},
				Responses: map[string]openapi.Response{
					"200": {
						Description: "Refreshed local session token and authenticated user context.",
						Content: map[string]openapi.MediaType{
							"application/json": {
								Schema: jsonschema.MustFor[schema.TokenResponse](),
							},
						},
					},
					"400": {
						Description: "Invalid token, malformed request, or refresh is not allowed for the referenced session.",
					},
				},
			},
		}
}

// Return an http.HandlerFunc for the openid configuration endpoint
func ConfigHandler(mgr *manager.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return oidc.ConfigPath, func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				_ = getOIDCConfig(r.Context(), mgr, w, r)
			default:
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
			}
		}, &openapi.PathItem{
			Summary:     "OpenID discovery document",
			Description: "Returns the OpenID Connect configuration for this server.",
		}
}

// Return an http.HandlerFunc for the JWKS endpoint
func JWKSHandler(mgr *manager.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return oidc.JWKSPath, func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				_ = getJWKS(r.Context(), mgr, w, r)
			default:
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
			}
		}, &openapi.PathItem{
			Summary:     "JSON Web Key Set",
			Description: "Returns the public signing keys for this server.",
		}
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func exchangeToken(ctx context.Context, mgr *manager.Manager, w http.ResponseWriter, r *http.Request) error {
	var req schema.TokenRequest
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else if claims, err := req.Validate(ctx); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else if identity, err := schema.NewIdentityFromClaims(claims); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else if user, session, err := mgr.LoginWithIdentity(ctx, identity); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else if config, err := mgr.OIDCConfig(r); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusInternalServerError).With(err))
	} else if token, err := mgr.OIDCSign(loginTokenClaims(config.Issuer, user, session)); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusInternalServerError).With(err))
	} else {
		return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), schema.TokenResponse{
			Token:   token,
			User:    *user,
			Session: *session,
		})
	}
}

func refreshToken(ctx context.Context, mgr *manager.Manager, w http.ResponseWriter, r *http.Request) error {
	var req schema.RefreshRequest
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else if token := strings.TrimSpace(req.Token); token == "" {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With("token is required"))
	} else if config, err := mgr.OIDCConfig(r); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusInternalServerError).With(err))
	} else if claims, err := mgr.OIDCVerify(req.Token, config.Issuer); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else if session, err := refreshSessionIDFromClaims(claims); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else if user, refreshed, err := mgr.RefreshSession(ctx, session); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else if token, err := mgr.OIDCSign(loginTokenClaims(config.Issuer, user, refreshed)); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusInternalServerError).With(err))
	} else {
		return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), schema.TokenResponse{
			Token:   token,
			User:    *user,
			Session: *refreshed,
		})
	}
}

func loginTokenClaims(issuer string, user *schema.User, session *schema.Session) jwt.MapClaims {
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss":     issuer,
		"sub":     uuid.UUID(user.ID).String(),
		"sid":     uuid.UUID(session.ID).String(),
		"iat":     now.Unix(),
		"nbf":     now.Unix(),
		"exp":     session.ExpiresAt.UTC().Unix(),
		"user":    user,
		"session": session,
	}
	if user.Email != "" {
		claims["email"] = user.Email
	}
	if user.Name != "" {
		claims["name"] = user.Name
	}
	if len(user.Groups) > 0 {
		claims["groups"] = user.Groups
	}
	if len(user.Scopes) > 0 {
		claims["scopes"] = user.Scopes
	}
	return claims
}

func refreshSessionIDFromClaims(claims map[string]any) (schema.SessionID, error) {
	value, ok := claims["sid"].(string)
	if !ok || strings.TrimSpace(value) == "" {
		return schema.SessionID{}, httpresponse.Err(http.StatusBadRequest).With("token missing sid claim")
	}
	return schema.SessionIDFromString(value)
}

func getOIDCConfig(_ context.Context, mgr *manager.Manager, w http.ResponseWriter, r *http.Request) error {
	config, err := mgr.OIDCConfig(r)
	if err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusInternalServerError).With(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), config)
}

func getJWKS(_ context.Context, mgr *manager.Manager, w http.ResponseWriter, r *http.Request) error {
	jwks, err := mgr.OIDCJWKSet()
	if err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusInternalServerError).With(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), jwks)
}
