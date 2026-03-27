package manager

import (
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"

	// Packages
	manager "github.com/djthorpe/go-auth/pkg/httpclient/manager"
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
	webcallback "github.com/djthorpe/go-auth/pkg/webcallback"
	server "github.com/mutablelogic/go-server"
	browser "github.com/pkg/browser"
	errgroup "golang.org/x/sync/errgroup"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

const defaultRedirectURL = "http://127.0.0.1:8085/callback"

type LoginCommand struct {
	Provider string `arg:"" optional:"" name:"provider" help:"Provider to login to. If not specified, the provider will be selected automatically if only one provider is configured."`
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *LoginCommand) Run(ctx server.Cmd) error {
	return withUnauthenticatedClient(ctx, func(manager *manager.Client, endpoint string) error {
		// Get the provider configuration to determine which provider to login to
		config, err := manager.Config(ctx.Context())
		if err != nil {
			return err
		}

		// Determine the provider, or choose the first one
		providers := slices.Collect(maps.Keys(config))
		if cmd.Provider == "" && len(providers) == 1 {
			cmd.Provider = providers[0]
		}
		if cmd.Provider == "" {
			return fmt.Errorf("multiple providers found in configuration, please specify one of: %v", providers)
		} else if cmd.Provider != "" && !slices.Contains(providers, cmd.Provider) {
			return fmt.Errorf("provider %q not found in configuration, available providers are: %q", cmd.Provider, providers)
		}

		// Get the authorization server metadata and configuration for the selected provider
		authconfig, err := manager.Discover(ctx.Context(), endpoint)
		if err != nil {
			return err
		}

		flowConfig, err := authconfig.AuthorizationCodeConfig()
		if err != nil {
			return err
		}
		flow, err := oidc.NewAuthorizationCodeFlow(flowConfig, "xxx", defaultRedirectURL, oidc.DefaultOIDCAuthorizationScopes...)
		if err != nil {
			return err
		}
		flow.Provider = cmd.Provider
		flow.AuthorizationURL, err = providerAuthorizationURL(flow.AuthorizationURL, cmd.Provider)
		if err != nil {
			return err
		}

		// Initiate the callback server to receive the authorization code response
		server, err := webcallback.New(defaultRedirectURL)
		if err != nil {
			return err
		}

		// In parallel, open the browser to the authorization URL and wait for the callback to be received,
		// then exchange the code for a token and store it
		g, groupCtx := errgroup.WithContext(ctx.Context())
		g.Go(func() error {
			result, err := server.Run(groupCtx)
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

			// Perform the token exchange and store the token
			token, err := manager.ExchangeCode(groupCtx, flow, code, "")
			if err != nil {
				return err
			}
			if err := NewCmdTokenStore(ctx).StoreToken(endpoint, flow.Issuer, token); err != nil {
				return err
			}
			ctx.Logger().Info("Stored login token", "issuer", flow.Issuer, "provider", cmd.Provider)
			return nil
		})
		g.Go(func() error {
			ctx.Logger().Info("Opening browser for authorization code flow", "url", flow.AuthorizationURL)
			return browser.OpenURL(flow.AuthorizationURL)
		})
		if err := g.Wait(); err != nil {
			return err
		}

		return nil
	})
}

func providerAuthorizationURL(rawURL, provider string) (string, error) {
	uri, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", err
	}
	query := uri.Query()
	query.Set("provider", strings.TrimSpace(provider))
	uri.RawQuery = query.Encode()
	return uri.String(), nil
}
