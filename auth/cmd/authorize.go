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

package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	// Packages
	auth "github.com/mutablelogic/go-auth/auth/httpclient"
	oidc "github.com/mutablelogic/go-auth/auth/oidc"
	webcallback "github.com/mutablelogic/go-auth/auth/webcallback"
	client "github.com/mutablelogic/go-client"
	server "github.com/mutablelogic/go-server"
	types "github.com/mutablelogic/go-server/pkg/types"
	browser "github.com/pkg/browser"
	oauth2 "golang.org/x/oauth2"
	errgroup "golang.org/x/sync/errgroup"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type AuthorizeCommand struct {
	Endpoint     string   `arg:"" optional:"" name:"endpoint" help:"Protected resource endpoint. Defaults to the stored endpoint or the global HTTP client endpoint."`
	Provider     string   `name:"provider" help:"Provider hint to pass to the authorization endpoint when multiple providers are configured."`
	ClientID     string   `name:"client-id" help:"OAuth client ID. Defaults to the stored client ID."`
	ClientSecret string   `name:"client-secret" help:"OAuth client secret. Defaults to the stored client secret when required by the provider."`
	Redirect     string   `name:"redirect-url" help:"OAuth callback URL for interactive login. When no port is specified, a free loopback port is chosen automatically." default:"http://localhost/"`
	Scopes       []string `name:"scope" help:"OAuth scopes to request. Repeat the flag to specify multiple scopes. Defaults to advertised OIDC scopes or openid email profile."`
}

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

const clientIDStoreKeyPrefix = "auth.client_id."
const clientSecretStoreKeyPrefix = "auth.client_secret."
const endpointStoreKeyPrefix = "auth.endpoint"
const issuerStoreKeyPrefix = "auth.issuer."
const tokenStoreKeyPrefix = "auth.token."
const defaultRedirectURL = "http://localhost/"

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *AuthorizeCommand) Run(ctx server.Cmd) error {
	auth_client, endpoint, err := clientFor(ctx)
	if err != nil {
		return err
	}

	// Set the endpoint
	if cmd.Endpoint == "" {
		cmd.Endpoint = endpoint
		if stored_endpoint := ctx.GetString(endpointStoreKeyPrefix); stored_endpoint != "" {
			cmd.Endpoint = stored_endpoint
		}
	}

	// Check the endpoint
	url, err := url.Parse(cmd.Endpoint)
	if err != nil {
		return fmt.Errorf("invalid endpoint URL: %w", err)
	} else if url.Scheme != types.SchemeSecure && url.Scheme != types.SchemeInsecure {
		return fmt.Errorf("endpoint URL must have http or https scheme")
	} else if url.Host == "" {
		return fmt.Errorf("endpoint URL must have a host")
	}

	// Retrieve stored token for the endpoint, if it exists and is valid, return it immediately
	token, err := storedToken(ctx, cmd.Endpoint)
	if err != nil {
		return err
	}

	// If the stored token is valid, return it immediately without going through the authorization flow
	if token != nil {
		if token.Valid() {
			data, err := json.MarshalIndent(token, "", "  ")
			if err != nil {
				return fmt.Errorf("marshal stored token: %w", err)
			}
			fmt.Println(string(data))
			return nil
		}
		refreshed, err := refreshStoredToken(ctx, auth_client, cmd.Endpoint, cmd.ClientID, cmd.ClientSecret)
		if err != nil {
			return err
		}
		data, err := json.MarshalIndent(refreshed, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal refreshed token: %w", err)
		}
		fmt.Println(string(data))
		return nil
	}

	// Attempt to get the protected resource metadata
	var meta *auth.Config
	if err := auth_client.DoAuthWithContext(ctx.Context(), nil, nil, client.OptReqEndpoint(cmd.Endpoint)); err != nil {
		meta_, err := auth_client.DiscoverWithError(ctx.Context(), err)
		if err == nil && meta_ != nil {
			meta = meta_
		}
	}

	// If meta is empty, we try and discover from the endpoint directly
	if meta == nil {
		meta_, err := auth_client.Discover(ctx.Context(), cmd.Endpoint)
		if err != nil {
			return fmt.Errorf("failed to discover auth server metadata: %w", err)
		} else {
			meta = meta_
		}
	}

	// Create the callback listener first so the resolved loopback URL, including
	// any auto-selected port, is used consistently for registration and the auth flow.
	redirectURL := strings.TrimSpace(cmd.Redirect)
	if redirectURL == "" {
		redirectURL = defaultRedirectURL
	}
	callback, err := webcallback.New(redirectURL)
	if err != nil {
		return err
	}
	redirectURL = callback.URL()

	// Get the server metadata and client ID for the authorization flow, either from the command line, stored value,
	// or dynamic registration
	serverMeta, clientID, clientSecret, err := cmd.authorizationServerAndClientCredentials(ctx, auth_client, meta, redirectURL)
	if err != nil {
		return err
	}

	// Generate the authorization code flow URL
	config, err := serverMeta.AuthorizationCodeConfig()
	if err != nil {
		return err
	}
	scopes := cmd.authorizationScopes(serverMeta)
	flow, err := oidc.NewAuthorizationCodeFlow(config, clientID, redirectURL, scopes...)
	if err != nil {
		return err
	}
	flow.Provider = strings.TrimSpace(cmd.Provider)
	flow.AuthorizationURL, err = authorizationURLWithHints(flow.AuthorizationURL, flow.Provider)
	if err != nil {
		return err
	}

	// In parallel, open the browser to the authorization URL and wait for the callback to be received,
	// then exchange the code for a token and store it
	g, groupCtx := errgroup.WithContext(ctx.Context())
	g.Go(func() error {
		result, err := callback.Run(groupCtx)
		if err != nil {
			return err
		}
		code, err := flow.ValidateCallback(
			result.Query.Get("code"),
			result.Query.Get("state"),
		)
		if err != nil {
			return err
		}
		token, err := auth_client.ExchangeCode(groupCtx, flow, code, clientSecret)
		if err != nil {
			return err
		}
		if err := storeToken(ctx, cmd.Endpoint, flow.Issuer, token); err != nil {
			return err
		}
		ctx.Logger().Debug("Stored authorization token", "issuer", flow.Issuer)
		return nil
	})
	g.Go(func() error {
		ctx.Logger().Info("Opening browser for authorization code flow", "url", flow.AuthorizationURL)
		return browser.OpenURL(flow.AuthorizationURL)
	})
	if err := g.Wait(); err != nil {
		return err
	}

	// Return success
	return nil
}

func (cmd *AuthorizeCommand) authorizationServerAndClientCredentials(ctx server.Cmd, authClient *auth.Client, meta *auth.Config, redirectURL string) (*auth.ServerMetadata, string, string, error) {
	// Retrieve client credentials from command line, stored values, or dynamic registration
	clientID := strings.TrimSpace(cmd.ClientID)
	if clientID == "" {
		clientID = storedClientID(ctx, meta, cmd.Endpoint)
	}
	clientSecret := strings.TrimSpace(cmd.ClientSecret)
	if clientSecret == "" {
		clientSecret = storedClientSecret(ctx, meta, cmd.Endpoint)
	}
	if clientID != "" {
		serverMeta, err := meta.AuthorizationServerForFlow()
		if err != nil {
			return nil, "", "", err
		}
		if err := storeClientCredentials(ctx, meta, cmd.Endpoint, clientID, clientSecret); err != nil {
			return nil, "", "", err
		}
		return serverMeta, clientID, clientSecret, nil
	}

	// Register client dynamically if client ID is not provided or stored
	serverMeta, err := meta.AuthorizationServerForRegistration()
	if err != nil {
		serverMeta, flowErr := meta.AuthorizationServerForFlow()
		if flowErr != nil {
			return nil, "", "", fmt.Errorf("client ID is required or dynamic registration must succeed: %w", err)
		}
		return serverMeta, "", clientSecret, nil
	}
	redirectURL = strings.TrimSpace(redirectURL)
	if redirectURL == "" {
		redirectURL = defaultRedirectURL
	}
	registration, err := authClient.RegisterClient(ctx.Context(), serverMeta, redirectURL)
	if err != nil {
		return nil, "", "", fmt.Errorf("client ID is required or dynamic registration must succeed: %w", err)
	}
	clientID = strings.TrimSpace(registration.ClientID)
	if clientID == "" {
		return nil, "", "", fmt.Errorf("registration did not return a client ID")
	}
	clientSecret = strings.TrimSpace(registration.ClientSecret)
	if err := storeClientCredentials(ctx, meta, cmd.Endpoint, clientID, clientSecret); err != nil {
		return nil, "", "", err
	}

	return serverMeta, clientID, clientSecret, nil
}

func (cmd *AuthorizeCommand) authorizationScopes(serverMeta *auth.ServerMetadata) []string {
	if scopes := compactScopes(cmd.Scopes); len(scopes) > 0 {
		return scopes
	}
	if serverMeta != nil {
		if strings.TrimSpace(serverMeta.Oidc.AuthorizationEndpoint) != "" {
			return oidc.AuthorizationScopes(serverMeta.Oidc)
		}
		if strings.TrimSpace(serverMeta.OAuth.AuthorizationEndpoint) != "" {
			return oidc.OAuthAuthorizationScopes(serverMeta.OAuth)
		}
	}
	return oidc.DefaultOIDCAuthorizationScopes
}

func compactScopes(scopes []string) []string {
	result := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope != "" {
			result = append(result, scope)
		}
	}
	return result
}

func authorizationURLWithHints(rawURL, provider string) (string, error) {
	uri, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", err
	}
	provider = strings.TrimSpace(provider)
	if provider != "" {
		query := uri.Query()
		query.Set("provider", provider)
		uri.RawQuery = query.Encode()
	}
	return uri.String(), nil
}

func storeToken(ctx server.Cmd, endpoint, issuer string, token *oauth2.Token) error {
	if ctx == nil || token == nil {
		return nil
	}
	endpoint = strings.TrimSpace(endpoint)
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return fmt.Errorf("issuer is required")
	}
	clone := *token
	if err := ctx.Set(tokenStoreKey(issuer), clone); err != nil {
		return fmt.Errorf("store token: %w", err)
	}
	if endpoint != "" {
		if err := ctx.Set(endpointStoreKeyPrefix, endpoint); err != nil {
			return fmt.Errorf("store endpoint: %w", err)
		}
		if err := ctx.Set(issuerStoreKey(endpoint), issuer); err != nil {
			return fmt.Errorf("store token issuer: %w", err)
		}
	}
	return nil
}

func deleteStoredToken(ctx server.Cmd, endpoint, issuer string) error {
	if ctx == nil {
		return nil
	}
	endpoint = strings.TrimSpace(endpoint)
	issuer = strings.TrimSpace(issuer)
	if issuer == "" && endpoint != "" {
		issuer = strings.TrimSpace(ctx.GetString(issuerStoreKey(endpoint)))
	}
	if issuer != "" {
		if err := ctx.Set(tokenStoreKey(issuer), nil); err != nil {
			return fmt.Errorf("delete token: %w", err)
		}
	}
	if endpoint != "" {
		if err := ctx.Set(issuerStoreKey(endpoint), nil); err != nil {
			return fmt.Errorf("delete token issuer: %w", err)
		}
	}
	return nil
}

func storedToken(ctx server.Cmd, endpoint string) (*oauth2.Token, error) {
	if ctx == nil {
		return nil, nil
	}
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return nil, nil
	}
	issuer := strings.TrimSpace(ctx.GetString(issuerStoreKey(endpoint)))
	if issuer != "" {
		if token, err := decodeStoredToken(ctx.Get(tokenStoreKey(issuer))); err != nil {
			return nil, err
		} else if token != nil {
			return token, nil
		}
	}
	return decodeStoredToken(ctx.Get(tokenStoreKey(endpoint)))
}

func decodeStoredToken(value any) (*oauth2.Token, error) {
	switch token := value.(type) {
	case nil:
		return nil, nil
	case oauth2.Token:
		clone := token
		return &clone, nil
	case *oauth2.Token:
		if token == nil {
			return nil, nil
		}
		clone := *token
		return &clone, nil
	default:
		data, err := json.Marshal(token)
		if err != nil {
			return nil, fmt.Errorf("decode stored token: %w", err)
		}
		var decoded oauth2.Token
		if err := json.Unmarshal(data, &decoded); err != nil {
			return nil, fmt.Errorf("decode stored token: %w", err)
		}
		if strings.TrimSpace(decoded.AccessToken) == "" {
			return nil, nil
		}
		return &decoded, nil
	}
}

func storedClientID(ctx server.Cmd, meta *auth.Config, endpoint string) string {
	if ctx == nil {
		return ""
	}
	return strings.TrimSpace(ctx.GetString(clientIDStoreKey(meta, endpoint)))
}

func storedClientSecret(ctx server.Cmd, meta *auth.Config, endpoint string) string {
	if ctx == nil {
		return ""
	}
	return strings.TrimSpace(ctx.GetString(clientSecretStoreKey(meta, endpoint)))
}

func storeClientCredentials(ctx server.Cmd, meta *auth.Config, endpoint, clientID, clientSecret string) error {
	if ctx == nil {
		return nil
	}
	clientID = strings.TrimSpace(clientID)
	clientSecret = strings.TrimSpace(clientSecret)
	if clientID != "" {
		if err := ctx.Set(clientIDStoreKey(meta, endpoint), clientID); err != nil {
			return fmt.Errorf("store client ID: %w", err)
		}
	}
	if clientSecret != "" {
		if err := ctx.Set(clientSecretStoreKey(meta, endpoint), clientSecret); err != nil {
			return fmt.Errorf("store client secret: %w", err)
		}
	}
	return nil
}

func clientIDStoreKey(meta *auth.Config, endpoint string) string {
	return clientCredentialStoreKey(clientIDStoreKeyPrefix, meta, endpoint)
}

func clientSecretStoreKey(meta *auth.Config, endpoint string) string {
	return clientCredentialStoreKey(clientSecretStoreKeyPrefix, meta, endpoint)
}

func clientCredentialStoreKey(prefix string, meta *auth.Config, endpoint string) string {
	key := strings.TrimSpace(endpoint)
	if meta != nil {
		for _, serverMeta := range meta.AuthorizationServers {
			if issuer := strings.TrimSpace(serverMeta.Issuer); issuer != "" {
				key = issuer
				break
			}
		}
		if key == "" {
			if resource := strings.TrimSpace(meta.ProtectedResourceMetadata.Resource); resource != "" {
				key = resource
			}
		}
	}
	if key == "" {
		key = "default"
	}
	return prefix + base64.RawURLEncoding.EncodeToString([]byte(key))
}

func tokenStoreKey(issuer string) string {
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		issuer = "default"
	}
	return tokenStoreKeyPrefix + base64.RawURLEncoding.EncodeToString([]byte(issuer))
}

func issuerStoreKey(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		endpoint = "default"
	}
	return issuerStoreKeyPrefix + base64.RawURLEncoding.EncodeToString([]byte(endpoint))
}
