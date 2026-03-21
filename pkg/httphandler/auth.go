package httphandler

import (
	"context"
	"net/http"
	"strings"
	"time"

	// Packages
	manager "github.com/djthorpe/go-auth/pkg/manager"
	middleware "github.com/djthorpe/go-auth/pkg/middleware"
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
	schema "github.com/djthorpe/go-auth/schema"
	jwt "github.com/golang-jwt/jwt/v5"
	uuid "github.com/google/uuid"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
	openapi "github.com/mutablelogic/go-server/pkg/openapi/schema"
)

var (
	validateTokenRequest = func(ctx context.Context, req *schema.TokenRequest) (map[string]any, error) {
		return req.Validate(ctx)
	}
	newIdentityFromClaims = schema.NewIdentityFromClaims
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
				Description: "Validates the upstream identity token, resolves the matching identity, and returns a signed local token plus userinfo.",
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
						Description: "Signed local session token and userinfo.",
						Content: map[string]openapi.MediaType{
							"application/json": {
								Schema: tokenResponseSchema(),
							},
						},
					},
					"400": {
						Description: "Invalid request body, unsupported provider, or token verification failure.",
					},
					"409": {
						Description: "The verified identity conflicts with an existing account.",
					},
				},
			},
		}
}

// Return an http.HandlerFunc for the public auth provider configuration endpoint.
func AuthConfigHandler(mgr *manager.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return "/auth/config", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				_ = getAuthConfig(r.Context(), mgr, w, r)
			default:
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
			}
		}, &openapi.PathItem{
			Summary:     "Public auth configuration",
			Description: "Returns the upstream authentication provider details that are safe to expose to clients.",
			Get: &openapi.Operation{
				Tags:        []string{"Auth"},
				Summary:     "Get public auth config",
				Description: "Returns the upstream issuer, client ID, and provider type used by clients to start authentication.",
				Responses: map[string]openapi.Response{
					"200": {
						Description: "Shareable upstream auth provider configurations.",
						Content: map[string]openapi.MediaType{
							"application/json": {
								Schema: jsonschema.MustFor[oidc.PublicClientConfigurations](),
							},
						},
					},
					"404": {
						Description: "No public auth provider configuration is available.",
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
						Description: "Refreshed local session token.",
						Content: map[string]openapi.MediaType{
							"application/json": {
								Schema: tokenResponseSchema(),
							},
						},
					},
					"400": {
						Description: "Invalid token, malformed request, or refresh is not allowed for the referenced session.",
					},
					"404": {
						Description: "The referenced session does not exist or is no longer refreshable.",
					},
				},
			},
		}
}

// Return an http.HandlerFunc for the auth revoke endpoint
func RevokeHandler(mgr *manager.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return "/auth/revoke", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodPost:
				_ = revokeToken(r.Context(), mgr, w, r)
			default:
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
			}
		}, &openapi.PathItem{
			Summary:     "Session revocation",
			Description: "Revoke a previously issued local session token so the underlying session can no longer be refreshed or accepted by session-aware checks.",
			Post: &openapi.Operation{
				Tags:        []string{"Auth"},
				Summary:     "Revoke session token",
				Description: "Verifies the supplied local session token and revokes the referenced session.",
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
					"204": {
						Description: "Session revoked.",
					},
					"400": {
						Description: "Invalid token, malformed request, or revocation failure.",
					},
					"404": {
						Description: "The referenced session does not exist or cannot be revoked.",
					},
				},
			},
		}
}

// Return an http.HandlerFunc for the auth userinfo endpoint
func UserInfoHandler(mgr *manager.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return "/auth/userinfo", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				_ = getUserInfo(r.Context(), mgr, w, r)
			default:
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
			}
		}, &openapi.PathItem{
			Summary:     "Authenticated user info",
			Description: "Returns the client-facing identity claims for the authenticated local token.",
			Get: &openapi.Operation{
				Tags:        []string{"Auth"},
				Summary:     "Get userinfo",
				Description: "Returns the authenticated userinfo derived from the current local bearer token.",
				Responses: map[string]openapi.Response{
					"200": {
						Description: "Authenticated userinfo.",
						Content: map[string]openapi.MediaType{
							"application/json": {
								Schema: userInfoSchema(),
							},
						},
					},
					"401": {
						Description: "Missing or invalid bearer token.",
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
	} else if claims, err := validateTokenRequest(ctx, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else if identity, err := newIdentityFromClaims(claims); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else if user, session, err := mgr.LoginWithIdentity(ctx, identity, req.Meta); err != nil {
		return httpresponse.Error(w, httpErr(err))
	} else if config, err := mgr.OIDCConfig(r); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusInternalServerError).With(err))
	} else if token, err := mgr.OIDCSign(loginTokenClaims(config.Issuer, user, session)); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusInternalServerError).With(err))
	} else {
		return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), schema.TokenResponse{
			Token:    token,
			UserInfo: schema.NewUserInfo(user),
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
	} else if session, err := sessionIDFromClaims(claims); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else if user, refreshed, err := mgr.RefreshSession(ctx, session); err != nil {
		return httpresponse.Error(w, httpErr(err))
	} else if token, err := mgr.OIDCSign(loginTokenClaims(config.Issuer, user, refreshed)); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusInternalServerError).With(err))
	} else {
		return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), schema.TokenResponse{
			Token: token,
		})
	}
}

func revokeToken(ctx context.Context, mgr *manager.Manager, w http.ResponseWriter, r *http.Request) error {
	var req schema.RefreshRequest
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else if token := strings.TrimSpace(req.Token); token == "" {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With("token is required"))
	} else if config, err := mgr.OIDCConfig(r); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusInternalServerError).With(err))
	} else if claims, err := mgr.OIDCVerify(req.Token, config.Issuer); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else if session, err := sessionIDFromClaims(claims); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else if _, err := mgr.RevokeSession(ctx, session); err != nil {
		return httpresponse.Error(w, httpErr(err))
	} else {
		w.WriteHeader(http.StatusNoContent)
		return nil
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

func sessionIDFromClaims(claims map[string]any) (schema.SessionID, error) {
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

func getAuthConfig(_ context.Context, mgr *manager.Manager, w http.ResponseWriter, r *http.Request) error {
	config, err := mgr.AuthConfig()
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
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

func getUserInfo(ctx context.Context, _ *manager.Manager, w http.ResponseWriter, r *http.Request) error {
	user, ok := middleware.UserFromContext(ctx)
	if !ok || user == nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusInternalServerError).With("authenticated user missing from context"))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), schema.NewUserInfo(user))
}
