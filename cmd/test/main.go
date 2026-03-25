package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	// Packages
	auth "github.com/djthorpe/go-auth/pkg/httpclient/auth2"
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
	ClientID  string                           `json:"client_id,omitempty"`
	Discovery *auth.ProtectedResourceDiscovery `json:"discovery,omitempty"`
	Flow      *oidc.AuthorizationCodeFlow      `json:"flow,omitempty"`
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
	authClient, err := auth.NewClient(endpoint, opts...)
	if err != nil {
		return err
	}

	response := &LoginResponse{ClientID: clientID}
	redirectURL := strings.TrimSpace(cmd.Redirect)
	if redirectURL == "" {
		redirectURL = defaultRedirectURL
	}
	var body bytes.Buffer
	if err := authClient.DoAuthWithContext(ctx.Context(), nil, &body); err != nil {
		var authErr *auth.AuthError
		if errors.As(err, &authErr) && authErr.Scheme != "" {
			discovery, err := authClient.DiscoverWithContext(ctx.Context(), err)
			if err != nil {
				return fmt.Errorf("failed to discover auth bootstrap: %w", err)
			}
			response.Discovery = discovery
			clientID, err = ensureClientID(ctx, authClient, discovery, endpoint, clientID, redirectURL)
			if err != nil {
				return err
			}
			response.ClientID = clientID
			response.Flow, err = discovery.AuthorizationCodeFlow(clientID, redirectURL)
			if err != nil {
				return err
			}
			return printLoginResponse(response)
		}
		return fmt.Errorf("request failed: %w", err)
	}

	discovery, err := authClient.DiscoverIssuerWithContext(ctx.Context(), endpoint)
	if err != nil {
		return fmt.Errorf("failed to discover auth server metadata: %w", err)
	}
	response.Discovery = discovery
	clientID, err = ensureClientID(ctx, authClient, discovery, endpoint, clientID, redirectURL)
	if err != nil {
		return err
	}
	response.ClientID = clientID
	response.Flow, err = discovery.AuthorizationCodeFlow(clientID, redirectURL)
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

func ensureClientID(ctx server.Cmd, authClient *auth.AuthClient, discovery *auth.ProtectedResourceDiscovery, endpoint, clientID, redirectURL string) (string, error) {
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
	registration, err := discovery.RegisterClientWithContext(ctx.Context(), authClient, redirectURL)
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

func storedClientID(ctx server.Cmd, discovery *auth.ProtectedResourceDiscovery, endpoint string) string {
	if ctx == nil {
		return ""
	}
	return strings.TrimSpace(ctx.GetString(clientIDStoreKey(discovery, endpoint)))
}

func storeClientID(ctx server.Cmd, discovery *auth.ProtectedResourceDiscovery, endpoint, clientID string) error {
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

func clientIDStoreKey(discovery *auth.ProtectedResourceDiscovery, endpoint string) string {
	key := strings.TrimSpace(endpoint)
	if discovery != nil {
		if len(discovery.AuthorizationServers) > 0 {
			if issuer := strings.TrimSpace(discovery.AuthorizationServers[0].Issuer); issuer != "" {
				key = issuer
			}
		} else if discovery.ResourceMetadata != nil {
			if resource := strings.TrimSpace(discovery.ResourceMetadata.Resource); resource != "" {
				key = resource
			}
		}
	}
	if key == "" {
		key = "default"
	}
	return clientIDStoreKeyPrefix + base64.RawURLEncoding.EncodeToString([]byte(key))
}
