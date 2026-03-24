package httphandler

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	// Packages
	coreoidc "github.com/coreos/go-oidc/v3/oidc"
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
	oauth2 "golang.org/x/oauth2"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// Return an http.HandlerFunc for the auth login endpoint
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

// Return an http.HandlerFunc for the local credentials login endpoint.
func AuthCredentialsHandler(mgr *manager.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return "/auth/credentials", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodPost:
				_ = loginWithCredentials(r.Context(), mgr, w, r)
			default:
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
			}
		}, &openapi.PathItem{
			Summary:     "Local credentials login",
			Description: "Creates or resolves a local testing identity using only an email address and returns a signed local token plus userinfo.",
			Post: &openapi.Operation{
				Tags:        []string{"Auth"},
				Summary:     "Login with local email",
				Description: "Uses the supplied email address to resolve or create a local testing identity and returns a signed local session token.",
				RequestBody: &openapi.RequestBody{
					Description: "Local testing login payload.",
					Required:    true,
					Content: map[string]openapi.MediaType{
						"application/json": {
							Schema: jsonschema.MustFor[schema.CredentialsRequest](),
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
						Description: "Invalid request body or malformed email address.",
					},
					"409": {
						Description: "The supplied email conflicts with an existing account that cannot be linked automatically.",
					},
				},
			},
		}
}

// Return an http.HandlerFunc for the auth code exchange endpoint.
func AuthCodeHandler(mgr *manager.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return "/auth/code", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodPost:
				_ = exchangeCode(r.Context(), mgr, w, r)
			default:
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
			}
		}, &openapi.PathItem{
			Summary:     "Authorization code exchange",
			Description: "Exchanges an OAuth authorization code using the server-side client secret, resolves the upstream identity, and returns a signed local token plus userinfo.",
			Post: &openapi.Operation{
				Tags:        []string{"Auth"},
				Summary:     "Exchange authorization code",
				Description: "Uses the configured upstream OAuth client to exchange an authorization code, verifies the resulting identity token, and returns a signed local session token.",
				RequestBody: &openapi.RequestBody{
					Description: "Provider key and authorization code produced by the browser-based login flow.",
					Required:    true,
					Content: map[string]openapi.MediaType{
						"application/json": {
							Schema: jsonschema.MustFor[schema.AuthorizationCodeRequest](),
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
						Description: "Invalid request body, unsupported provider, or upstream code exchange failure.",
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
	} else if claims, err := req.Validate(ctx); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else {
		return issueLoginResponse(ctx, mgr, w, r, claims, req.Meta)
	}
}

func exchangeCode(ctx context.Context, mgr *manager.Manager, w http.ResponseWriter, r *http.Request) error {
	var req schema.AuthorizationCodeRequest
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else if err := req.Validate(); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else if claims, err := exchangeAuthorizationCode(ctx, mgr, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else {
		return issueLoginResponse(ctx, mgr, w, r, claims, req.Meta)
	}
}

func loginWithCredentials(ctx context.Context, mgr *manager.Manager, w http.ResponseWriter, r *http.Request) error {
	var req schema.CredentialsRequest
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else if err := req.Validate(); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	}

	identity := schema.IdentityInsert{
		IdentityKey: schema.IdentityKey{
			Provider: oidc.OAuthClientKeyLocal,
			Sub:      req.Email,
		},
		IdentityMeta: schema.IdentityMeta{
			Email:  req.Email,
			Claims: map[string]any{"email": req.Email},
		},
	}

	return issueIdentityLoginResponse(ctx, mgr, w, r, identity, req.Meta)
}

func refreshToken(ctx context.Context, mgr *manager.Manager, w http.ResponseWriter, r *http.Request) error {
	var req schema.RefreshRequest
	token := ""
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else if token = strings.TrimSpace(req.Token); token == "" {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With("token is required"))
	} else if config, err := mgr.OIDCConfig(r); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusInternalServerError).With(err))
	} else if claims, err := mgr.OIDCVerify(token, config.Issuer); err != nil {
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
	token := ""
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else if token = strings.TrimSpace(req.Token); token == "" {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With("token is required"))
	} else if config, err := mgr.OIDCConfig(r); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusInternalServerError).With(err))
	} else if claims, err := mgr.OIDCVerify(token, config.Issuer); err != nil {
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

func issueLoginResponse(ctx context.Context, mgr *manager.Manager, w http.ResponseWriter, r *http.Request, claims map[string]any, meta schema.MetaMap) error {
	if identity, err := schema.NewIdentityFromClaims(claims); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else {
		return issueIdentityLoginResponse(ctx, mgr, w, r, identity, meta)
	}
}

func issueIdentityLoginResponse(ctx context.Context, mgr *manager.Manager, w http.ResponseWriter, r *http.Request, identity schema.IdentityInsert, meta schema.MetaMap) error {
	if user, session, err := mgr.LoginWithIdentity(ctx, identity, meta); err != nil {
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

func exchangeAuthorizationCode(ctx context.Context, mgr *manager.Manager, req *schema.AuthorizationCodeRequest) (map[string]any, error) {
	config, err := mgr.OAuthClientConfig(req.Provider)
	if err != nil {
		return nil, err
	}
	provider, err := coreoidc.NewProvider(ctx, config.Issuer)
	if err != nil {
		return nil, err
	}
	oauthConfig := &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  req.RedirectURL,
		Endpoint:     provider.Endpoint(),
	}
	options := make([]oauth2.AuthCodeOption, 0, 1)
	if verifier := strings.TrimSpace(req.CodeVerifier); verifier != "" {
		options = append(options, oauth2.SetAuthURLParam("code_verifier", verifier))
	}
	token, err := oauthConfig.Exchange(ctx, req.Code, options...)
	if err != nil {
		return nil, err
	}
	rawIDToken, _ := token.Extra("id_token").(string)
	rawIDToken = strings.TrimSpace(rawIDToken)
	if rawIDToken == "" {
		return nil, fmt.Errorf("upstream token response missing id_token")
	}
	verified, err := provider.Verifier(&coreoidc.Config{ClientID: config.ClientID}).Verify(ctx, rawIDToken)
	if err != nil {
		return nil, err
	}
	claims := make(map[string]any)
	if err := verified.Claims(&claims); err != nil {
		return nil, err
	}
	if err := validateAuthorizationCodeNonce(req.Nonce, claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func validateAuthorizationCodeNonce(expected string, claims map[string]any) error {
	expected = strings.TrimSpace(expected)
	if expected == "" {
		return nil
	}
	actual, _ := claims["nonce"].(string)
	if strings.TrimSpace(actual) != expected {
		return fmt.Errorf("token nonce mismatch")
	}
	return nil
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
