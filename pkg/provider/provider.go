package provider

import (
	"context"
	"net/http"

	// Packages
	schema "github.com/djthorpe/go-auth/schema"
	openapi "github.com/mutablelogic/go-server/pkg/openapi/schema"
)

///////////////////////////////////////////////////////////////////////////////
// INTERFACES

// Provider defines the browser and code-exchange hooks for an identity provider.
type Provider interface {
	// Key returns the stable provider key.
	Key() string

	// PublicConfig returns the safe-to-expose client configuration.
	PublicConfig() schema.PublicClientConfiguration

	// HTTPHandler returns the provider-owned browser handler for caller-defined mounts.
	// The OpenAPI path item may be nil.
	HTTPHandler() (http.HandlerFunc, *openapi.PathItem)

	// BeginAuthorization starts the browser authorization flow.
	BeginAuthorization(context.Context, AuthorizationRequest) (*AuthorizationResponse, error)

	// ExchangeAuthorizationCode converts a code into a normalized identity,
	// which can be inserted into the database and used to issue local session tokens.
	ExchangeAuthorizationCode(context.Context, ExchangeRequest) (*schema.IdentityInsert, error)
}

///////////////////////////////////////////////////////////////////////////////
// TYPES

type AuthorizationRequest struct {
	RedirectURL         string
	ProviderURL         string
	State               string
	Scopes              []string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	LoginHint           string
}

type AuthorizationResponse struct {
	RedirectURL string
}

type ExchangeRequest struct {
	Code         string
	RedirectURL  string
	CodeVerifier string
	Nonce        string
}
