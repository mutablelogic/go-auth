package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	// Packages
	auth "github.com/djthorpe/go-auth/pkg/httpclient/auth"
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
	client "github.com/mutablelogic/go-client"
	server "github.com/mutablelogic/go-server"
	cmd "github.com/mutablelogic/go-server/pkg/cmd"
	version "github.com/mutablelogic/go-server/pkg/version"
)

const endpointStoreKey = "test.endpoint"
const defaultRedirectURL = "http://127.0.0.1:8085/callback"
const clientIDStoreKeyPrefix = "test.client_id."

type CLI struct {
	Login LoginCommand `cmd:"" name:"login" help:"Discover auth bootstrap metadata for a protected resource endpoint."`
}

type LoginCommand struct {
	Endpoint string `arg:"" optional:"" name:"endpoint" help:"Protected resource endpoint. Defaults to the stored endpoint or the global HTTP client endpoint."`
	ClientID string `name:"client-id" help:"OAuth client ID. Defaults to the stored client ID."`
	Redirect string `name:"redirect-url" help:"OAuth callback URL for interactive login." default:"http://127.0.0.1:8085/callback"`
}

type LoginResponse struct {
	ClientID  string                      `json:"client_id,omitempty"`
	Discovery *auth.Config                `json:"discovery,omitempty"`
	Flow      *oidc.AuthorizationCodeFlow `json:"flow,omitempty"`
}

func main() {
	if err := cmd.Main(CLI{}, "Auth discovery test client", version.Version()); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(-1)
	}
}

func (cmd *LoginCommand) Run(ctx server.Cmd) error {
	endpoint, opts, err := endpointFor(ctx, cmd.Endpoint)
	if err != nil {
		return err
	}
	clientID := strings.TrimSpace(cmd.ClientID)
	authClient, err := auth.New(endpoint, opts...)
	if err != nil {
		return err
	}

	response := &LoginResponse{ClientID: clientID}
	redirectURL := strings.TrimSpace(cmd.Redirect)
	if redirectURL == "" {
		redirectURL = defaultRedirectURL
	}
	var discovery *auth.Config
	if err := authClient.DoAuthWithContext(ctx.Context(), nil, nil, client.OptReqEndpoint(endpoint)); err != nil {
		discovery, err = authClient.DiscoverWithError(ctx.Context(), err)
		if err != nil {
			return fmt.Errorf("failed to discover auth bootstrap: %w", err)
		}
	} else {
		discovery, err = authClient.Discover(ctx.Context(), endpoint)
		if err != nil {
			return fmt.Errorf("failed to discover auth server metadata: %w", err)
		}
	}
	response.Discovery = discovery
	clientID, err = ensureClientID(ctx, authClient, discovery, endpoint, clientID, redirectURL)
	if err != nil {
		return err
	}
	response.ClientID = clientID
	serverMeta, err := authorizationServerForFlow(discovery)
	if err != nil {
		return err
	}
	config, err := authorizationCodeConfig(serverMeta)
	if err != nil {
		return err
	}
	response.Flow, err = oidc.NewAuthorizationCodeFlow(config, clientID, redirectURL)
	if err != nil {
		return err
	}
	return printLoginResponse(response)
}

func printLoginResponse(response *LoginResponse) error {
	data, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode auth bootstrap: %w", err)
	}
	fmt.Println(string(data))
	return nil
}

func ensureClientID(ctx server.Cmd, authClient *auth.Client, discovery *auth.Config, endpoint, clientID, redirectURL string) (string, error) {
	if clientID = strings.TrimSpace(clientID); clientID != "" {
		if err := storeClientID(ctx, discovery, endpoint, clientID); err != nil {
			return "", err
		}
		return clientID, nil
	}
	if discovery == nil {
		return "", fmt.Errorf("client ID is required")
	}
	if clientID := storedClientID(ctx, discovery, endpoint); clientID != "" {
		return clientID, nil
	}
	serverMeta, err := authorizationServerForRegistration(discovery)
	if err != nil {
		return "", fmt.Errorf("client ID is required or dynamic registration must succeed: %w", err)
	}
	registration, err := authClient.RegisterClient(ctx.Context(), serverMeta, redirectURL)
	if err != nil {
		return "", fmt.Errorf("client ID is required or dynamic registration must succeed: %w", err)
	}
	clientID = strings.TrimSpace(registration.ClientID)
	if clientID == "" {
		return "", fmt.Errorf("registration did not return a client ID")
	}
	if err := storeClientID(ctx, discovery, endpoint, clientID); err != nil {
		return "", err
	}
	return clientID, nil
}

func endpointFor(ctx server.Cmd, value string) (string, []client.ClientOpt, error) {
	if ctx == nil {
		return "", nil, fmt.Errorf("command context is required")
	}
	configuredEndpoint, opts, err := ctx.ClientEndpoint()
	if err != nil {
		return "", nil, err
	}
	if endpoint := strings.TrimSpace(value); endpoint != "" {
		if err := ctx.Set(endpointStoreKey, endpoint); err != nil {
			return "", nil, fmt.Errorf("store endpoint: %w", err)
		}
		return endpoint, opts, nil
	}
	if endpoint := strings.TrimSpace(ctx.GetString(endpointStoreKey)); endpoint != "" {
		return endpoint, opts, nil
	}
	if endpoint := strings.TrimSpace(configuredEndpoint); endpoint != "" {
		return endpoint, opts, nil
	}
	return "", nil, fmt.Errorf("endpoint is required")
}

func storedClientID(ctx server.Cmd, discovery *auth.Config, endpoint string) string {
	if ctx == nil {
		return ""
	}
	return strings.TrimSpace(ctx.GetString(clientIDStoreKey(discovery, endpoint)))
}

func storeClientID(ctx server.Cmd, discovery *auth.Config, endpoint, clientID string) error {
	if ctx == nil {
		return nil
	}
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return nil
	}
	if err := ctx.Set(clientIDStoreKey(discovery, endpoint), clientID); err != nil {
		return fmt.Errorf("store client ID: %w", err)
	}
	return nil
}

func clientIDStoreKey(discovery *auth.Config, endpoint string) string {
	key := strings.TrimSpace(endpoint)
	if discovery != nil {
		for _, serverMeta := range discovery.AuthorizationServers {
			if issuer := strings.TrimSpace(serverMeta.Issuer); issuer != "" {
				key = issuer
				break
			}
		}
		if key == "" {
			if resource := strings.TrimSpace(discovery.ProtectedResourceMetadata.Resource); resource != "" {
				key = resource
			}
		}
	}
	if key == "" {
		key = "default"
	}
	return clientIDStoreKeyPrefix + base64.RawURLEncoding.EncodeToString([]byte(key))
}

func authorizationServerForFlow(meta *auth.Config) (*auth.ServerMetadata, error) {
	if meta == nil || len(meta.AuthorizationServers) == 0 {
		return nil, fmt.Errorf("authorization server metadata is required")
	}
	for index := range meta.AuthorizationServers {
		serverMeta := &meta.AuthorizationServers[index]
		if strings.TrimSpace(serverMeta.Oidc.AuthorizationEndpoint) != "" || strings.TrimSpace(serverMeta.OAuth.AuthorizationEndpoint) != "" {
			return serverMeta, nil
		}
	}
	return nil, fmt.Errorf("no authorization endpoint is advertised")
}

func authorizationServerForRegistration(meta *auth.Config) (*auth.ServerMetadata, error) {
	if meta == nil || len(meta.AuthorizationServers) == 0 {
		return nil, fmt.Errorf("authorization server metadata is required")
	}
	for index := range meta.AuthorizationServers {
		serverMeta := &meta.AuthorizationServers[index]
		if strings.TrimSpace(serverMeta.OAuth.RegistrationEndpoint) != "" &&
			(strings.TrimSpace(serverMeta.Oidc.AuthorizationEndpoint) != "" || strings.TrimSpace(serverMeta.OAuth.AuthorizationEndpoint) != "") {
			return serverMeta, nil
		}
	}
	for index := range meta.AuthorizationServers {
		serverMeta := &meta.AuthorizationServers[index]
		if strings.TrimSpace(serverMeta.OAuth.RegistrationEndpoint) != "" {
			return serverMeta, nil
		}
	}
	return nil, fmt.Errorf("no registration endpoint is advertised")
}

func authorizationCodeConfig(serverMeta *auth.ServerMetadata) (oidc.BaseConfiguration, error) {
	if strings.TrimSpace(serverMeta.Oidc.AuthorizationEndpoint) != "" {
		config := serverMeta.Oidc.BaseConfiguration
		if strings.TrimSpace(config.Issuer) == "" {
			config.Issuer = strings.TrimSpace(serverMeta.Issuer)
		}
		config.NonceSupported = true
		return config, nil
	} else if strings.TrimSpace(serverMeta.OAuth.AuthorizationEndpoint) != "" {
		config := serverMeta.OAuth.BaseConfiguration
		if strings.TrimSpace(config.Issuer) == "" {
			config.Issuer = strings.TrimSpace(serverMeta.Issuer)
		}
		config.NonceSupported = false
		return config, nil
	}
	return oidc.BaseConfiguration{}, fmt.Errorf("no authorization endpoint is advertised")
}
