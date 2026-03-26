package auth

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"

	// Packages
	client "github.com/mutablelogic/go-client"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type ClientRegistrationRequest struct {
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
}

type ClientRegistrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at,omitempty"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	RegistrationClientURI   string   `json:"registration_client_uri,omitempty"`
	RegistrationAccessToken string   `json:"registration_access_token,omitempty"`
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// RegisterClient registers a client against the supplied authorization server metadata.
func (c *Client) RegisterClient(ctx context.Context, server *ServerMetadata, redirectURI string) (*ClientRegistrationResponse, error) {
	if server == nil {
		return nil, fmt.Errorf("authorization server metadata is required")
	}
	request, endpoint, err := registrationRequest(server, &ClientRegistrationRequest{
		RedirectURIs: []string{strings.TrimSpace(redirectURI)},
	})
	if err != nil {
		return nil, err
	}
	payload, err := client.NewJSONRequestEx(http.MethodPost, request, "application/json")
	if err != nil {
		return nil, fmt.Errorf("registration payload: %w", err)
	}
	var response ClientRegistrationResponse
	if err := c.Client.DoWithContext(ctx, payload, &response, client.OptReqEndpoint(endpoint)); err != nil {
		return nil, fmt.Errorf("register client at %q: %w", endpoint, err)
	}
	response.ClientID = strings.TrimSpace(response.ClientID)
	if response.ClientID == "" {
		return nil, fmt.Errorf("register client at %q: missing client_id in response", endpoint)
	}
	return &response, nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func registrationRequest(server *ServerMetadata, req *ClientRegistrationRequest) (*ClientRegistrationRequest, string, error) {
	if server == nil {
		return nil, "", fmt.Errorf("authorization server metadata is required")
	}
	request := &ClientRegistrationRequest{}
	if req != nil {
		*request = *req
		request.RedirectURIs = append([]string(nil), req.RedirectURIs...)
		request.GrantTypes = append([]string(nil), req.GrantTypes...)
		request.ResponseTypes = append([]string(nil), req.ResponseTypes...)
	}
	request.RedirectURIs = compactStrings(request.RedirectURIs)
	request.GrantTypes = compactStrings(request.GrantTypes)
	request.ResponseTypes = compactStrings(request.ResponseTypes)
	request.TokenEndpointAuthMethod = strings.TrimSpace(request.TokenEndpointAuthMethod)
	request.ClientName = strings.TrimSpace(request.ClientName)
	request.Scope = strings.TrimSpace(request.Scope)

	if len(request.RedirectURIs) == 0 {
		return nil, "", fmt.Errorf("at least one redirect URI is required for client registration")
	}
	endpoint, grantTypes, responseTypes, authMethods := registrationMetadata(server)
	if endpoint == "" {
		return nil, "", fmt.Errorf("registration endpoint is not advertised")
	}
	if len(request.GrantTypes) == 0 {
		request.GrantTypes = preferredValues(grantTypes, "authorization_code")
	}
	if len(request.ResponseTypes) == 0 {
		request.ResponseTypes = preferredValues(responseTypes, "code")
	}
	if request.TokenEndpointAuthMethod == "" {
		request.TokenEndpointAuthMethod = preferredValue(authMethods, "none")
	}
	if request.ClientName == "" {
		request.ClientName = "go-auth"
	}

	return request, endpoint, nil
}

func registrationMetadata(server *ServerMetadata) (string, []string, []string, []string) {
	if server == nil {
		return "", nil, nil, nil
	}
	if endpoint := strings.TrimSpace(server.Oidc.RegistrationEndpoint); endpoint != "" {
		return endpoint, server.Oidc.GrantTypesSupported, server.Oidc.ResponseTypes, server.Oidc.TokenEndpointAuthMethodsSupported
	}
	if endpoint := strings.TrimSpace(server.OAuth.RegistrationEndpoint); endpoint != "" {
		return endpoint, server.OAuth.GrantTypesSupported, server.OAuth.ResponseTypes, server.OAuth.TokenEndpointAuthMethodsSupported
	}
	return "", nil, nil, nil
}

func preferredValues(values []string, preferred string) []string {
	value := preferredValue(values, preferred)
	if value == "" {
		return nil
	}
	return []string{value}
}

func preferredValue(values []string, preferred string) string {
	values = compactStrings(values)
	if len(values) == 0 {
		return ""
	}
	if preferred != "" && slices.Contains(values, preferred) {
		return preferred
	}
	return values[0]
}

func compactStrings(values []string) []string {
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
