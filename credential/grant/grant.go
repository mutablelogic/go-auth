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

// Package grant is the source of the access tokens of a sign-in, which is
// stored as a credential, such as by POST /credential/{key}/signin: the
// token is refreshed, with the secret of the client, which is another
// credential, and stored again, once it has expired.
package grant

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strings"
	"sync"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	authclient "github.com/mutablelogic/go-auth/auth/httpclient"
	credential "github.com/mutablelogic/go-auth/credential"
	oauth2 "golang.org/x/oauth2"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// Config is the sign-in which a source's tokens are of
type Config struct {
	Server   authclient.ServerMetadata // The authorization server, such as Google
	Client   string                    // The key of the credential of its OAuth client, such as GOOGLE_CLIENT
	Key      string                    // The key of the credential of the sign-in, such as GOOGLE_TOKEN
	Required []string                  // The sign-in has one of these scopes
	Scopes   []string                  // The scopes which are asked for, when signing in
}

// Credentials are what a source reads its client, and sign-in, from, and
// stores the sign-in to, which a credential.CredentialProvider is
type Credentials interface {
	// Get returns the credential for the key, as JSON
	Get(ctx context.Context, key string) (json.RawMessage, error)

	// Set stores the credential for the key, which is JSON
	Set(ctx context.Context, key string, value json.RawMessage) error
}

// Source is the source of the access tokens of a sign-in, which is safe to
// use from more than one goroutine
type Source struct {
	mu          sync.Mutex
	config      Config
	credentials Credentials
	client      authclient.Registration
	current     authclient.Grant
	refresher   *authclient.Client
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// New returns the source of the access tokens of the sign-in, which must be
// the server's, for the client, and have one of the required scopes.
// Returns a SignInError, with how to sign in, which wraps
// ErrInvalidProvider, when the person hasn't, or their sign-in is for
// another client, or doesn't have the scopes. Returns ErrServiceUnavailable
// when there are no credentials, or no client, as no one can sign in, and
// ErrBadParameter when the client isn't one.
func New(ctx context.Context, credentials Credentials, config Config) (*Source, error) {
	if credentials == nil {
		return nil, auth.ErrServiceUnavailable.Withf("can't sign in with %s, without a provider of credentials", config.Server.Issuer)
	}
	refresher, err := authclient.New(config.Server.Issuer)
	if err != nil {
		return nil, err
	}
	self := &Source{config: config, credentials: credentials, refresher: refresher}
	client, err := self.readClient(ctx)
	if err != nil {
		return nil, err
	}
	self.client = *client
	current, err := self.read(ctx)
	if err != nil {
		return nil, err
	}
	self.current = *current
	return self, nil
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// Token returns the sign-in's token, which is refreshed, and stored, under
// the key's credential.Lock, once it has expired. A sign-in which was
// replaced while it was refreshed, such as when the person signed in again,
// is used, rather than overwritten. Returns a SignInError when the sign-in
// is revoked, or expired, and ErrServiceUnavailable when the server refuses
// the client, such as when its secret is wrong, which signing in again
// doesn't mend, or the server fails.
func (self *Source) Token(ctx context.Context) (*oauth2.Token, error) {
	self.mu.Lock()
	defer self.mu.Unlock()

	// The sign-in, as it's stored, which the person can replace, by signing
	// in again
	current, err := self.read(ctx)
	if err != nil {
		return nil, err
	}
	self.current = *current
	if current.Token.Valid() {
		return current.Token, nil
	}

	// Refresh it, with the client's secret, which isn't stored with it
	grant := *current
	grant.Client = self.client
	token, err := self.refresher.TokenSource(ctx, &grant, nil).Token()
	var retrieve *oauth2.RetrieveError
	switch {
	case errors.As(err, &retrieve) && (retrieve.ErrorCode == "invalid_client" || retrieve.ErrorCode == "unauthorized_client"):
		return nil, auth.ErrServiceUnavailable.Withf("%s refused the client of %q, so check its client_id and client_secret: %v", self.config.Server.Issuer, self.config.Client, err)
	case errors.Is(err, auth.ErrBadParameter):
		// Refused, as it's revoked, or expired, or can't be refreshed
		return nil, self.signIn(current, auth.ErrInvalidProvider.Withf("sign-in %q is revoked, or expired, so sign in with %s again: %v", self.config.Key, self.config.Server.Issuer, err))
	case err != nil:
		return nil, auth.ErrServiceUnavailable.Withf("refreshing sign-in %q: %v", self.config.Key, err)
	}

	// Store it, unless it was replaced meanwhile, under the key's lock
	unlock := credential.Lock(self.config.Key)
	defer unlock()
	if latest, err := self.read(ctx); err != nil {
		return nil, err
	} else if !sameToken(latest.Token, current.Token) {
		self.current = *latest
		return latest.Token, nil
	}
	refreshed := *current
	refreshed.Token = token
	if refreshed.Token.RefreshToken == "" {
		refreshed.Token.RefreshToken = current.Token.RefreshToken
	}
	data, err := json.Marshal(refreshed)
	if err != nil {
		return nil, err
	} else if err := self.credentials.Set(ctx, self.config.Key, data); err != nil {
		return nil, err
	}
	self.current = refreshed
	return refreshed.Token, nil
}

// SignIn returns a SignInError, which wraps the error, with how to sign in
// again, such as when an API doesn't accept the token, as it's revoked
func (self *Source) SignIn(err error) error {
	self.mu.Lock()
	current := self.current
	self.mu.Unlock()
	return self.signIn(&current, err)
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// read returns the sign-in, which must be the server's, for the client, and
// have one of the required scopes, or a SignInError
func (self *Source) read(ctx context.Context) (*authclient.Grant, error) {
	key, issuer := self.config.Key, self.config.Server.Issuer
	data, err := self.credentials.Get(ctx, key)
	if errors.Is(err, auth.ErrNotFound) {
		return nil, self.signIn(nil, auth.ErrInvalidProvider.Withf("no %q sign-in, so sign in with %s", key, issuer))
	} else if err != nil {
		return nil, err
	}
	var grant authclient.Grant
	if err := json.Unmarshal(data, &grant); err != nil {
		return nil, self.signIn(nil, auth.ErrInvalidProvider.Withf("credential %q isn't a sign-in: %v", key, err))
	}
	switch {
	case grant.Server.Issuer != issuer:
		return nil, self.signIn(nil, auth.ErrInvalidProvider.Withf("sign-in %q isn't of %s, so sign in with it", key, issuer))
	case grant.Client.ClientID != self.client.ClientID:
		return nil, self.signIn(&grant, auth.ErrInvalidProvider.Withf("sign-in %q is for another client than %q's, so sign in with %s again", key, self.config.Client, issuer))
	case grant.Token == nil || (grant.Token.AccessToken == "" && grant.Token.RefreshToken == ""):
		return nil, self.signIn(&grant, auth.ErrInvalidProvider.Withf("sign-in %q has no token, so sign in with %s again", key, issuer))
	case len(self.config.Required) > 0 && !hasScope(grant.Scopes, self.config.Required):
		return nil, self.signIn(&grant, auth.ErrInvalidProvider.Withf("sign-in %q doesn't have the access which is needed, %s, so sign in with %s again", key, strings.Join(self.config.Required, " or "), issuer))
	}
	if u, err := url.Parse(grant.Server.TokenEndpoint); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, self.signIn(&grant, auth.ErrInvalidProvider.Withf("sign-in %q has no token endpoint, so sign in with %s again", key, issuer))
	}
	return &grant, nil
}

// signIn returns a SignInError, with how the person signs in: the server,
// the client, and the scopes, with those the sign-in has, when it isn't
// nil, so signing in again doesn't take away what others need
func (self *Source) signIn(grant *authclient.Grant, err error) error {
	scopes := slices.Clone(self.config.Scopes)
	if grant != nil {
		for _, scope := range grant.Scopes {
			if !slices.Contains(scopes, scope) {
				scopes = append(scopes, scope)
			}
		}
	}
	return authclient.NewSignInError(authclient.SignIn{
		Server:     self.config.Server,
		ClientID:   self.client.ClientID,
		Scopes:     scopes,
		Credential: self.config.Key,
	}, err)
}

// readClient returns the client, which is ErrServiceUnavailable when
// there's none, as no one can sign in
func (self *Source) readClient(ctx context.Context) (*authclient.Registration, error) {
	data, err := self.credentials.Get(ctx, self.config.Client)
	if errors.Is(err, auth.ErrNotFound) {
		return nil, auth.ErrServiceUnavailable.Withf("can't sign in with %s: no %q credential, with the client_id and client_secret of its OAuth client", self.config.Server.Issuer, self.config.Client)
	} else if err != nil {
		return nil, err
	}
	client, err := authclient.ParseRegistration(data)
	if err != nil {
		return nil, auth.ErrBadParameter.Withf("credential %q: %v", self.config.Client, err)
	}
	return client, nil
}

// sameToken returns true when two tokens are the same
func sameToken(a, b *oauth2.Token) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.AccessToken == b.AccessToken && a.RefreshToken == b.RefreshToken && a.Expiry.Equal(b.Expiry)
}

// hasScope returns true when the scopes have one of those which are required
func hasScope(scopes, required []string) bool {
	for _, scope := range required {
		if slices.Contains(scopes, scope) {
			return true
		}
	}
	return false
}
