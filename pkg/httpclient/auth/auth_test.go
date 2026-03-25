package auth

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	// Packages
	authcrypto "github.com/djthorpe/go-auth/pkg/crypto"
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
	authschema "github.com/djthorpe/go-auth/schema"
	jwt "github.com/golang-jwt/jwt/v5"
	uuid "github.com/google/uuid"
	client "github.com/mutablelogic/go-client"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
	oauth2 "golang.org/x/oauth2"
)

func TestIssueToken(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		key := mustRSAKey(t)
		claims := jwt.MapClaims{
			"iss":   "https://issuer.example.com",
			"email": "alice@example.com",
		}
		before := time.Now().UTC()

		token, err := oidc.IssueToken(key, claims)
		require.NoError(t, err)
		assert.NotEmpty(t, token)
		assert.Contains(t, claims, "iat")
		assert.Contains(t, claims, "nbf")
		assert.Contains(t, claims, "exp")
		assert.GreaterOrEqual(t, claims["iat"], before.Unix())
		assert.GreaterOrEqual(t, claims["nbf"], before.Unix())
		assert.Greater(t, claims["exp"], claims["iat"])
	})

	t.Run("MissingClaims", func(t *testing.T) {
		_, err := oidc.IssueToken(mustRSAKey(t), nil)
		require.Error(t, err)
	})

	t.Run("MissingIssuer", func(t *testing.T) {
		_, err := oidc.IssueToken(mustRSAKey(t), jwt.MapClaims{"email": "alice@example.com"})
		require.Error(t, err)
	})

	t.Run("MissingKeyUsesNoneAlgorithm", func(t *testing.T) {
		token, err := oidc.IssueToken(nil, jwt.MapClaims{"iss": "https://issuer.example.com"})
		require.NoError(t, err)
		assert.NotEmpty(t, token)

		parsed, err := jwt.Parse(token, func(token *jwt.Token) (any, error) {
			assert.Equal(t, jwt.SigningMethodNone.Alg(), token.Method.Alg())
			return jwt.UnsafeAllowNoneSignatureType, nil
		})
		require.NoError(t, err)
		assert.True(t, parsed.Valid)
	})
}

func TestClientAuthMethods(t *testing.T) {
	t.Run("LoginPostsProviderToken", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		key := mustRSAKey(t)
		var request authschema.TokenRequest
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodPost, r.Method)
			require.Equal("/auth/login", r.URL.Path)
			require.NoError(json.NewDecoder(r.Body).Decode(&request))
			require.Equal(authschema.ProviderOAuth, request.Provider)

			issuer, err := oidc.ExtractIssuer(request.Token)
			require.NoError(err)
			assert.Equal("https://issuer.example.test", issuer)

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(authschema.TokenResponse{
				Token: "local-token",
				UserInfo: &authschema.UserInfo{
					Sub:   authschema.UserID(uuid.New()),
					Name:  "Alice",
					Email: "alice@example.com",
				},
			}))
		}))
		defer server.Close()

		client, err := New(server.URL)
		require.NoError(err)
		response, err := client.Login(context.Background(), key, jwt.MapClaims{
			"iss":   "https://issuer.example.test",
			"email": "alice@example.com",
		})
		require.NoError(err)
		require.NotNil(response)
		assert.Equal("local-token", response.Token)
		require.NotNil(response.UserInfo)
		assert.Equal("alice@example.com", response.UserInfo.Email)
	})

	t.Run("LoginTokenPostsProviderToken", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		var request authschema.TokenRequest
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodPost, r.Method)
			require.Equal("/auth/login", r.URL.Path)
			require.NoError(json.NewDecoder(r.Body).Decode(&request))
			assert.Equal(authschema.ProviderOAuth, request.Provider)
			assert.Equal("upstream-token", request.Token)

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(authschema.TokenResponse{Token: "local-token"}))
		}))
		defer server.Close()

		client, err := New(server.URL)
		require.NoError(err)
		response, err := client.LoginToken(context.Background(), " upstream-token ")
		require.NoError(err)
		require.NotNil(response)
		assert.Equal("local-token", response.Token)
	})

	t.Run("LoginCodePostsAuthorizationCode", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		var request authschema.AuthorizationCodeRequest
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodPost, r.Method)
			require.Equal("/auth/code", r.URL.Path)
			require.NoError(json.NewDecoder(r.Body).Decode(&request))
			assert.Equal("google", request.Provider)
			assert.Equal("auth-code", request.Code)
			assert.Equal("http://127.0.0.1:8085/callback", request.RedirectURL)
			assert.Equal("code-verifier", request.CodeVerifier)
			assert.Equal("nonce-123", request.Nonce)

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(authschema.TokenResponse{Token: "local-token"}))
		}))
		defer server.Close()

		client, err := New(server.URL)
		require.NoError(err)
		response, err := client.LoginCode(context.Background(), "google", &oidc.AuthorizationCodeFlow{
			RedirectURL:  "http://127.0.0.1:8085/callback",
			CodeVerifier: "code-verifier",
			Nonce:        "nonce-123",
		}, " auth-code ")
		require.NoError(err)
		require.NotNil(response)
		assert.Equal("local-token", response.Token)
	})

	t.Run("LoginRejectsMissingIssuer", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		server := httptest.NewServer(http.NotFoundHandler())
		defer server.Close()

		client, err := New(server.URL)
		require.NoError(err)
		response, err := client.Login(context.Background(), mustRSAKey(t), jwt.MapClaims{"email": "alice@example.com"})
		require.Error(err)
		assert.Nil(response)
	})

	t.Run("RefreshPostsToken", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		var request authschema.RefreshRequest
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodPost, r.Method)
			require.Equal("/auth/refresh", r.URL.Path)
			require.NoError(json.NewDecoder(r.Body).Decode(&request))
			assert.Equal("refresh-token", request.Token)

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(authschema.TokenResponse{
				Token: "refreshed-token",
			}))
		}))
		defer server.Close()

		client, err := New(server.URL)
		require.NoError(err)
		response, err := client.Refresh(context.Background(), "refresh-token")
		require.NoError(err)
		require.NotNil(response)
		assert.Equal("refreshed-token", response.Token)
		assert.Nil(response.UserInfo)
	})

	t.Run("UserInfoUsesBearerToken", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodGet, r.Method)
			require.Equal("/auth/userinfo", r.URL.Path)
			assert.Equal("Bearer local-token", r.Header.Get("Authorization"))

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(authschema.UserInfo{
				Sub:   authschema.UserID(uuid.New()),
				Name:  "Alice",
				Email: "alice@example.com",
			}))
		}))
		defer server.Close()

		client, err := New(server.URL)
		require.NoError(err)
		response, err := client.UserInfo(context.Background(), " local-token ")
		require.NoError(err)
		require.NotNil(response)
		assert.Equal("alice@example.com", response.Email)
		assert.Equal("Alice", response.Name)
	})

	t.Run("OIDCConfigGetsDiscoveryDocument", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodGet, r.Method)
			require.Equal("/"+oidc.ConfigPath, r.URL.Path)

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(oidc.Configuration{
				Issuer:                "https://issuer.example.test/api",
				AuthorizationEndpoint: "https://issuer.example.test/api/oauth/authorize",
				TokenEndpoint:         "https://issuer.example.test/api/oauth/token",
				UserInfoEndpoint:      "https://issuer.example.test/api/auth/userinfo",
				JwksURI:               oidc.JWKSURL("https://issuer.example.test/api"),
				SigningAlgorithms:     []string{oidc.SigningAlgorithm},
				SubjectTypes:          []string{"public"},
				ResponseTypes:         []string{"code", "id_token"},
				GrantTypesSupported:   []string{"authorization_code"},
				ScopesSupported:       []string{oidc.ScopeOpenID, oidc.ScopeEmail, oidc.ScopeProfile},
				CodeChallengeMethods:  []string{"S256"},
				ClaimsSupported:       []string{"iss", "sub"},
			}))
		}))
		defer server.Close()

		client, err := New("https://unused.example.test")
		require.NoError(err)
		response, err := client.OIDCConfig(context.Background(), server.URL)
		require.NoError(err)
		require.NotNil(response)
		assert.Equal("https://issuer.example.test/api", response.Issuer)
		assert.Equal("https://issuer.example.test/api/oauth/authorize", response.AuthorizationEndpoint)
		assert.Equal("https://issuer.example.test/api/oauth/token", response.TokenEndpoint)
		assert.Equal(oidc.JWKSURL("https://issuer.example.test/api"), response.JwksURI)
		assert.Equal([]string{oidc.SigningAlgorithm}, response.SigningAlgorithms)
	})

	t.Run("OIDCConfigRequiresIssuer", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		client, err := New("https://unused.example.test")
		require.NoError(err)

		response, err := client.OIDCConfig(context.Background(), "")
		require.Error(err)
		assert.Nil(response)
	})

	t.Run("AuthConfigGetsPublicProviderConfig", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodGet, r.Method)
			require.Equal("/auth/config", r.URL.Path)

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(oidc.PublicClientConfigurations{
				"google": {
					Issuer:   oidc.GoogleIssuer,
					ClientID: "google-client-id",
					Provider: authschema.ProviderOAuth,
				},
			}))
		}))
		defer server.Close()

		client, err := New(server.URL)
		require.NoError(err)
		response, err := client.AuthConfig(context.Background())
		require.NoError(err)
		google, ok := response["google"]
		require.True(ok)
		assert.Equal(oidc.GoogleIssuer, google.Issuer)
		assert.Equal("google-client-id", google.ClientID)
		assert.Equal(authschema.ProviderOAuth, google.Provider)
	})

	t.Run("OAuth2ConfigResolvesGoogleProvider", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		var discovery *httptest.Server
		discovery = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodGet, r.Method)
			require.Equal("/"+oidc.ConfigPath, r.URL.Path)

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(oidc.Configuration{
				Issuer:                discovery.URL,
				AuthorizationEndpoint: discovery.URL + "/o/oauth2/v2/auth",
				TokenEndpoint:         discovery.URL + "/token",
				JwksURI:               oidc.JWKSURL(discovery.URL),
				SigningAlgorithms:     []string{oidc.SigningAlgorithm},
				SubjectTypes:          []string{"public"},
				ResponseTypes:         []string{"code"},
				GrantTypesSupported:   []string{"authorization_code"},
				ScopesSupported:       []string{oidc.ScopeOpenID, oidc.ScopeEmail, oidc.ScopeProfile},
				CodeChallengeMethods:  []string{"S256"},
				ClaimsSupported:       []string{"iss", "sub", "email"},
			}))
		}))
		defer discovery.Close()

		authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodGet, r.Method)
			require.Equal("/auth/config", r.URL.Path)

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(oidc.PublicClientConfigurations{
				"google": {
					Issuer:   discovery.URL,
					ClientID: "google-client-id",
					Provider: authschema.ProviderOAuth,
				},
			}))
		}))
		defer authServer.Close()

		client, err := New(authServer.URL)
		require.NoError(err)

		config, err := client.OAuth2Config(context.Background(), "google", "http://127.0.0.1:8085/callback")
		require.NoError(err)
		require.NotNil(config)
		assert.Equal("google-client-id", config.ClientID)
		assert.Equal("http://127.0.0.1:8085/callback", config.RedirectURL)
		assert.Equal(discovery.URL+"/o/oauth2/v2/auth", config.Endpoint.AuthURL)
		assert.Equal(discovery.URL+"/token", config.Endpoint.TokenURL)
		assert.Equal([]string{oidc.ScopeOpenID, oidc.ScopeEmail, oidc.ScopeProfile}, config.Scopes)
	})

	t.Run("OAuth2ConfigRejectsProviderWithoutClientID", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodGet, r.Method)
			require.Equal("/auth/config", r.URL.Path)

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(oidc.PublicClientConfigurations{
				oidc.OAuthClientKeyLocal: {
					Issuer:   "https://issuer.example.test/api",
					Provider: authschema.ProviderOAuth,
				},
			}))
		}))
		defer server.Close()

		client, err := New(server.URL)
		require.NoError(err)

		config, err := client.OAuth2Config(context.Background(), "", "http://127.0.0.1:8085/callback")
		require.Error(err)
		assert.Nil(config)
		assert.EqualError(err, `auth provider "local" has no client_id`)
	})

	t.Run("FetchConfigBuildsOAuth2ConfigFromIssuer", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		var server *httptest.Server
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodGet, r.Method)
			require.Equal("/"+oidc.ConfigPath, r.URL.Path)

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(oidc.Configuration{
				Issuer:                server.URL,
				AuthorizationEndpoint: server.URL + "/authorize",
				TokenEndpoint:         server.URL + "/token",
				JwksURI:               oidc.JWKSURL(server.URL),
				SigningAlgorithms:     []string{oidc.SigningAlgorithm},
				SubjectTypes:          []string{"public"},
				ResponseTypes:         []string{"code"},
				GrantTypesSupported:   []string{"authorization_code"},
				ScopesSupported:       []string{oidc.ScopeOpenID, oidc.ScopeEmail, oidc.ScopeProfile},
				ClaimsSupported:       []string{"iss", "sub", "email"},
			}))
		}))
		defer server.Close()

		config, err := FetchConfig(context.Background(), server.URL, "github-client-id", "http://127.0.0.1:8085/callback")
		require.NoError(err)
		require.NotNil(config)
		assert.Equal("github-client-id", config.ClientID)
		assert.Equal("http://127.0.0.1:8085/callback", config.RedirectURL)
		assert.Equal(server.URL+"/authorize", config.Endpoint.AuthURL)
		assert.Equal(server.URL+"/token", config.Endpoint.TokenURL)
		assert.Equal([]string{oidc.ScopeOpenID, oidc.ScopeEmail, oidc.ScopeProfile}, config.Scopes)
	})

	t.Run("FetchConfigIncludesWWWAuthenticateHeader", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodGet, r.Method)
			require.Equal("/"+oidc.ConfigPath, r.URL.Path)
			w.Header().Set("WWW-Authenticate", `Bearer realm="github", error="not_authorized"`)
			http.Error(w, "not authorized", http.StatusUnauthorized)
		}))
		defer server.Close()

		config, err := FetchConfig(context.Background(), server.URL, "github-client-id", "http://127.0.0.1:8085/callback")
		require.Error(err)
		assert.Nil(config)
		assert.ErrorContains(err, "401 Unauthorized")
		assert.ErrorContains(err, "WWW-Authenticate")
		assert.ErrorContains(err, `Bearer realm="github", error="not_authorized"`)
	})

	t.Run("AuthCodeURLBuildsAuthorizationURL", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		var discovery *httptest.Server
		discovery = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(oidc.Configuration{
				Issuer:                discovery.URL,
				AuthorizationEndpoint: discovery.URL + "/authorize",
				TokenEndpoint:         discovery.URL + "/token",
				JwksURI:               oidc.JWKSURL(discovery.URL),
				SigningAlgorithms:     []string{oidc.SigningAlgorithm},
				SubjectTypes:          []string{"public"},
				ResponseTypes:         []string{"code"},
				ClaimsSupported:       []string{"iss", "sub"},
			}))
		}))
		defer discovery.Close()

		authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(oidc.PublicClientConfigurations{
				"google": {
					Issuer:   discovery.URL,
					ClientID: "google-client-id",
					Provider: authschema.ProviderOAuth,
				},
			}))
		}))
		defer authServer.Close()

		client, err := New(authServer.URL)
		require.NoError(err)

		uri, err := client.AuthCodeURL(context.Background(), "google", "http://127.0.0.1:8085/callback", "state-123")
		require.NoError(err)
		assert.Contains(uri, "client_id=google-client-id")
		assert.Contains(uri, "redirect_uri=http%3A%2F%2F127.0.0.1%3A8085%2Fcallback")
		assert.Contains(uri, "response_type=code")
		assert.Contains(uri, "scope=openid+email+profile")
		assert.Contains(uri, "state=state-123")
	})

	t.Run("OAuthLoginBootstrapResolvesGoogleProvider", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		var discovery *httptest.Server
		discovery = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodGet, r.Method)
			require.Equal("/"+oidc.ConfigPath, r.URL.Path)

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(oidc.Configuration{
				Issuer:                discovery.URL,
				AuthorizationEndpoint: discovery.URL + "/o/oauth2/v2/auth",
				TokenEndpoint:         discovery.URL + "/token",
				UserInfoEndpoint:      discovery.URL + "/userinfo",
				JwksURI:               oidc.JWKSURL(discovery.URL),
				SigningAlgorithms:     []string{oidc.SigningAlgorithm},
				SubjectTypes:          []string{"public"},
				ResponseTypes:         []string{"code"},
				GrantTypesSupported:   []string{"authorization_code"},
				ScopesSupported:       []string{oidc.ScopeOpenID, oidc.ScopeEmail, oidc.ScopeProfile},
				CodeChallengeMethods:  []string{"plain", "S256"},
				ClaimsSupported:       []string{"iss", "sub", "email"},
			}))
		}))
		defer discovery.Close()

		authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodGet, r.Method)
			require.Equal("/auth/config", r.URL.Path)

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(oidc.PublicClientConfigurations{
				"google": {
					Issuer:   discovery.URL,
					ClientID: "google-client-id",
					Provider: authschema.ProviderOAuth,
				},
			}))
		}))
		defer authServer.Close()

		client, err := New(authServer.URL)
		require.NoError(err)

		bootstrap, err := client.OAuthLoginBootstrap(context.Background(), "google", "http://127.0.0.1:8085/callback")
		require.NoError(err)
		require.NotNil(bootstrap)
		assert.Equal(discovery.URL, bootstrap.Issuer)
		assert.Equal("google-client-id", bootstrap.ClientID)
		assert.Equal("http://127.0.0.1:8085/callback", bootstrap.RedirectURL)
		assert.Equal(discovery.URL+"/o/oauth2/v2/auth", bootstrap.AuthorizationEndpoint)
		assert.Contains(bootstrap.AuthorizationURL, discovery.URL+"/o/oauth2/v2/auth")
		assert.Contains(bootstrap.AuthorizationURL, "client_id=google-client-id")
		assert.Equal(discovery.URL+"/token", bootstrap.TokenEndpoint)
		assert.Equal([]string{oidc.ScopeOpenID, oidc.ScopeEmail, oidc.ScopeProfile}, bootstrap.Scopes)
		assert.NotEmpty(bootstrap.State)
		assert.NotEmpty(bootstrap.Nonce)
		assert.NotEmpty(bootstrap.CodeVerifier)
		assert.NotEmpty(bootstrap.CodeChallenge)
		assert.Equal(oidc.CodeChallengeMethodS256, bootstrap.CodeChallengeMethod)
	})

	t.Run("OAuthLoginBootstrapRejectsLocalProviderWithoutClientID", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodGet, r.Method)
			require.Equal("/auth/config", r.URL.Path)

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(oidc.PublicClientConfigurations{
				oidc.OAuthClientKeyLocal: {
					Issuer:   "https://issuer.example.test/api",
					Provider: authschema.ProviderOAuth,
				},
			}))
		}))
		defer authServer.Close()

		client, err := New(authServer.URL)
		require.NoError(err)

		bootstrap, err := client.OAuthLoginBootstrap(context.Background(), oidc.OAuthClientKeyLocal, "http://127.0.0.1:8085/callback")
		require.Error(err)
		assert.Nil(bootstrap)
		assert.EqualError(err, `auth provider "local" has no client_id`)
	})

	t.Run("ExchangeAuthorizationCodeReturnsIDToken", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodPost, r.Method)
			require.Equal("/token", r.URL.Path)
			require.NoError(r.ParseForm())
			assert.Equal("authorization_code", r.PostForm.Get("grant_type"))
			assert.Equal("auth-code-123", r.PostForm.Get("code"))
			assert.Equal("http://127.0.0.1:8085/callback", r.PostForm.Get("redirect_uri"))
			assert.Equal("verifier-123", r.PostForm.Get("code_verifier"))

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(map[string]any{
				"access_token": "access-token",
				"token_type":   "Bearer",
				"id_token":     "id-token",
			}))
		}))
		defer server.Close()

		client, err := New("https://unused.example.test")
		require.NoError(err)

		idToken, err := client.ExchangeAuthorizationCode(context.Background(), &oidc.AuthorizationCodeFlow{
			AuthorizationEndpoint: server.URL + "/authorize",
			TokenEndpoint:         server.URL + "/token",
			ClientID:              "client-id",
			RedirectURL:           "http://127.0.0.1:8085/callback",
			CodeVerifier:          "verifier-123",
		}, " auth-code-123 ")
		require.NoError(err)
		assert.Equal("id-token", idToken)
	})

	t.Run("ExchangeAuthorizationCodeRequiresIDToken", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(map[string]any{
				"access_token": "access-token",
				"token_type":   "Bearer",
			}))
		}))
		defer server.Close()

		client, err := New("https://unused.example.test")
		require.NoError(err)

		idToken, err := client.ExchangeAuthorizationCode(context.Background(), &oidc.AuthorizationCodeFlow{
			TokenEndpoint: server.URL,
			ClientID:      "client-id",
			RedirectURL:   "http://127.0.0.1:8085/callback",
		}, "auth-code-123")
		require.Error(err)
		assert.Equal("", idToken)
		assert.EqualError(err, "upstream token response missing id_token")
	})

	t.Run("AuthConfigUnauthorizedIncludesRecordedHeaders", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		const authConfigHeader = `</auth/config>; rel="oauth-config"`
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodGet, r.Method)
			require.Equal("/auth/config", r.URL.Path)
			assert.Equal(authConfigHeader, r.Header.Get("Link"))
			w.Header().Set("WWW-Authenticate", `Bearer realm="auth", error="invalid_token"`)
			http.Error(w, "not authorized", http.StatusUnauthorized)
		}))
		defer server.Close()

		client, err := New(server.URL, client.OptHeader("Link", authConfigHeader))
		require.NoError(err)

		response, err := client.AuthConfig(context.Background())
		require.Error(err)
		assert.Nil(response)
		assert.ErrorContains(err, "401 Unauthorized")
		assert.ErrorContains(err, "WWW-Authenticate: Bearer realm=\"auth\", error=\"invalid_token\"")
		assert.ErrorContains(err, "Link: </auth/config>; rel=\"oauth-config\"")
	})

	t.Run("ExchangeAuthorizationCodeUnauthorizedIncludesRecordedHeaders", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		const authConfigHeader = `</auth/config>; rel="oauth-config"`
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodPost, r.Method)
			require.True(strings.HasSuffix(r.URL.Path, "/token"))
			assert.Equal(authConfigHeader, r.Header.Get("Link"))
			w.Header().Set("WWW-Authenticate", `Bearer realm="issuer", error="invalid_client"`)
			http.Error(w, "invalid client", http.StatusUnauthorized)
		}))
		defer server.Close()

		client, err := New("https://unused.example.test", client.OptHeader("Link", authConfigHeader))
		require.NoError(err)

		idToken, err := client.ExchangeAuthorizationCode(context.Background(), &oidc.AuthorizationCodeFlow{
			AuthorizationEndpoint: server.URL + "/authorize",
			TokenEndpoint:         server.URL + "/token",
			ClientID:              "client-id",
			RedirectURL:           "http://127.0.0.1:8085/callback",
		}, "auth-code-123")
		require.Error(err)
		assert.Equal("", idToken)
		assert.ErrorContains(err, "invalid_client")
		assert.ErrorContains(err, "WWW-Authenticate: Bearer realm=\"issuer\", error=\"invalid_client\"")
		assert.ErrorContains(err, "Link: </auth/config>; rel=\"oauth-config\"")
	})

	t.Run("RevokePostsToken", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		var request authschema.RefreshRequest
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodPost, r.Method)
			require.Equal("/auth/revoke", r.URL.Path)
			require.NoError(json.NewDecoder(r.Body).Decode(&request))
			assert.Equal("revoke-token", request.Token)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		client, err := New(server.URL)
		require.NoError(err)
		require.NoError(client.Revoke(context.Background(), "revoke-token"))
	})

	t.Run("RefreshPropagatesServerError", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "bad token", http.StatusBadRequest)
		}))
		defer server.Close()

		client, err := New(server.URL)
		require.NoError(err)
		response, err := client.Refresh(context.Background(), "bad-token")
		require.Error(err)
		assert.Nil(response)
	})

	t.Run("TokenSourceReturnsCurrentToken", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("unexpected refresh request: %s %s", r.Method, r.URL.Path)
		}))
		defer server.Close()

		client, err := New(server.URL)
		require.NoError(err)

		current, err := oidc.IssueToken(nil, jwt.MapClaims{
			"iss": "https://issuer.example.test",
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		require.NoError(err)

		source, err := client.TokenSource(context.Background(), current)
		require.NoError(err)

		token, err := source.Token()
		require.NoError(err)
		require.NotNil(token)
		assert.Equal(current, token.AccessToken)
		assert.Equal("Bearer", token.Type())
	})

	t.Run("TokenSourceRefreshesExpiredToken", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		refreshedToken, err := oidc.IssueToken(nil, jwt.MapClaims{
			"iss": "https://issuer.example.test",
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		require.NoError(err)

		var request authschema.RefreshRequest
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodPost, r.Method)
			require.Equal("/auth/refresh", r.URL.Path)
			require.NoError(json.NewDecoder(r.Body).Decode(&request))

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(authschema.TokenResponse{Token: refreshedToken}))
		}))
		defer server.Close()

		client, err := New(server.URL)
		require.NoError(err)

		expired, err := oidc.IssueToken(nil, jwt.MapClaims{
			"iss": "https://issuer.example.test",
			"exp": time.Now().Add(-time.Hour).Unix(),
		})
		require.NoError(err)

		source, err := client.TokenSource(context.Background(), expired)
		require.NoError(err)

		token, err := source.Token()
		require.NoError(err)
		require.NotNil(token)
		assert.Equal(expired, request.Token)
		assert.Equal(refreshedToken, token.AccessToken)
		assert.True(token.Expiry.After(time.Now()))
	})

	t.Run("TokenSourceRejectsMalformedToken", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		client, err := New("https://issuer.example.test")
		require.NoError(err)

		source, err := client.TokenSource(context.Background(), "not-a-jwt")
		require.Error(err)
		assert.Nil(source)
	})

	t.Run("TokenSourceImplementsOAuth2Interface", func(t *testing.T) {
		client, err := New("https://issuer.example.test")
		require.NoError(t, err)

		token, err := oidc.IssueToken(nil, jwt.MapClaims{
			"iss": "https://issuer.example.test",
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		require.NoError(t, err)

		source, err := client.TokenSource(context.Background(), token)
		require.NoError(t, err)

		var tokenSource oauth2.TokenSource = source
		assert.NotNil(t, tokenSource)
	})
}

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := authcrypto.GeneratePrivateKey()
	require.NoError(t, err)
	return key
}
