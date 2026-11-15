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

package bitwarden

import (
	"net/http"
	"net/url"
	"os"
	"strings"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	credential "github.com/mutablelogic/go-auth/credential"
	env "github.com/mutablelogic/go-auth/credential/env"
	trace "go.opentelemetry.io/otel/trace"
)

////////////////////////////////////////////////////////////////////////////////
// TYPES

// Opt is a functional option for the Bitwarden credential manager
type Opt func(*opt) error

type opt struct {
	tracer      trace.Tracer
	accessToken string
	apiURL      string
	identityURL string
	projectIDs  []string
	http        *http.Client
	env         credential.CredentialProvider
	useEnv      bool
}

////////////////////////////////////////////////////////////////////////////////
// GLOBALS

const (
	// The environment variables, which are the bws command's
	envAccessToken = "BWS_ACCESS_TOKEN"
	envServerURL   = "BWS_SERVER_URL"

	// The servers for Bitwarden's US cloud
	defaultAPIURL      = "https://api.bitwarden.com"
	defaultIdentityURL = "https://identity.bitwarden.com"
)

////////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func (o *opt) apply(opts []Opt) error {
	// Defaults, from the environment
	o.accessToken = os.Getenv(envAccessToken)
	o.apiURL, o.identityURL = defaultAPIURL, defaultIdentityURL
	if server := os.Getenv(envServerURL); server != "" {
		if err := WithServerURL(server)(o); err != nil {
			return err
		}
	}
	o.http = http.DefaultClient

	// Apply options
	for _, fn := range opts {
		if err := fn(o); err != nil {
			return err
		}
	}

	// The environment provider uses the tracer, which can be set after
	// WithEnv
	if o.useEnv {
		o.env = env.New(env.WithTracer(o.tracer))
	}
	return nil
}

////////////////////////////////////////////////////////////////////////////////
// OPTIONS

// WithTracer sets the tracer used for tracing operations
func WithTracer(tracer trace.Tracer) Opt {
	return func(o *opt) error {
		o.tracer = tracer
		return nil
	}
}

// WithAccessToken sets the machine account's access token, in place of
// BWS_ACCESS_TOKEN
func WithAccessToken(token string) Opt {
	return func(o *opt) error {
		if token == "" {
			return auth.ErrBadParameter.With("access token is empty")
		}
		o.accessToken = token
		return nil
	}
}

// WithServerURL sets the server of a self-hosted Bitwarden, in place of
// BWS_SERVER_URL, whose API is at /api and identity server at /identity
func WithServerURL(server string) Opt {
	return func(o *opt) error {
		server = strings.TrimSuffix(server, "/")
		if err := validateURL(server); err != nil {
			return err
		}
		o.apiURL, o.identityURL = server+"/api", server+"/identity"
		return nil
	}
}

// WithURLs sets the API and identity servers, such as
// https://api.bitwarden.eu and https://identity.bitwarden.eu for
// Bitwarden's EU cloud
func WithURLs(api, identity string) Opt {
	return func(o *opt) error {
		api, identity = strings.TrimSuffix(api, "/"), strings.TrimSuffix(identity, "/")
		if err := validateURL(api); err != nil {
			return err
		} else if err := validateURL(identity); err != nil {
			return err
		}
		o.apiURL, o.identityURL = api, identity
		return nil
	}
}

// WithProject adds a project, by its identifier, which new secrets are
// created in. A machine account can usually only create secrets in a
// project it can write to.
func WithProject(id string) Opt {
	return func(o *opt) error {
		if !isUUID(id) {
			return auth.ErrBadParameter.Withf("project %q is not a UUID", id)
		}
		o.projectIDs = append(o.projectIDs, strings.ToLower(id))
		return nil
	}
}

// WithHTTPClient sets the HTTP client, in place of http.DefaultClient
func WithHTTPClient(client *http.Client) Opt {
	return func(o *opt) error {
		if client == nil {
			return auth.ErrBadParameter.With("http client is nil")
		}
		o.http = client
		return nil
	}
}

// WithEnv reads a credential from the environment when there is no secret
// for it, so $KEY is expanded from the environment variable KEY. The
// environment is read-only, so credentials are still stored as secrets.
func WithEnv() Opt {
	return func(o *opt) error {
		o.useEnv = true
		return nil
	}
}

////////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// validateURL returns an error if the value isn't an http or https URL
func validateURL(value string) error {
	if u, err := url.Parse(value); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return auth.ErrBadParameter.Withf("%q is not an http or https URL", value)
	}
	return nil
}
