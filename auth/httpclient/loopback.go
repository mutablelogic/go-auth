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

package httpclient

import (
	"context"
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	// Packages
	goauth "github.com/mutablelogic/go-auth"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// Loopback is a callback, on the loopback interface, at a port which is
// free, which a command's authorization redirects to, as RFC 8252 has it,
// so it's waited for
type Loopback struct {
	listener net.Listener
	server   *http.Server
	queries  chan url.Values
}

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

// CallbackPath is the path of a loopback's callback
const CallbackPath = "/callback"

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// NewLoopback listens for a callback, on 127.0.0.1, until it's closed
func NewLoopback() (*Loopback, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	l := &Loopback{listener: listener, queries: make(chan url.Values, 1)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+CallbackPath, l.callback)
	l.server = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go l.server.Serve(listener)
	return l, nil
}

// Close stops listening
func (l *Loopback) Close() error {
	return l.server.Close()
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// RedirectURI is the URI the authorization redirects to
func (l *Loopback) RedirectURI() string {
	return "http://" + l.listener.Addr().String() + CallbackPath
}

// Wait returns the query of the first callback, which has the code, and
// the state, or the error the authorization server said, or the context's
// error
func (l *Loopback) Wait(ctx context.Context) (url.Values, error) {
	select {
	case query := <-l.queries:
		return query, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// callback passes the first callback's query on, and says, in the browser,
// whether it's authorized
func (l *Loopback) callback(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	select {
	case l.queries <- query:
	default:
		http.Error(w, "The authorization was already completed", http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if reason := query.Get("error"); reason != "" {
		if description := query.Get("error_description"); description != "" {
			reason = description
		}
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "<!DOCTYPE html><title>Not signed in</title><p>It wasn't authorized: %s</p>", html.EscapeString(reason))
		return
	}
	fmt.Fprint(w, "<!DOCTYPE html><title>Signed in</title><p>Signed in. You can close this window.</p>")
}

///////////////////////////////////////////////////////////////////////////////
// LOGIN

// Login authorizes the resource, for a command: how is discovered, from
// the error, when it's an AuthError, which a request to it returned, or
// else from the resource, and a client, which is given, or else
// registered, with the name, is authorized, with a loopback callback, at
// the URL open opens, such as in a browser, and returns the grant, with its
// token. It waits until it's authorized, or the context is done.
func (c *Client) Login(ctx context.Context, err error, name string, client *Registration, open func(string) error, scopes ...string) (*Grant, error) {
	if open == nil {
		return nil, goauth.ErrBadParameter.With("nothing opens the authorization")
	}
	var metadata *Metadata
	if authErr := AsAuthError(err); authErr != nil {
		// The scopes the challenge says are needed, unless they're given
		if len(scopes) == 0 && authErr.Get("scope") != "" {
			scopes = strings.Fields(authErr.Get("scope"))
		}
		metadata, err = c.DiscoverWithError(ctx, err)
	} else {
		metadata, err = c.Discover(ctx, "")
	}
	if err != nil {
		return nil, err
	}

	// The callback, and the client, which is registered with it
	loopback, err := NewLoopback()
	if err != nil {
		return nil, err
	}
	defer loopback.Close()
	registration := client
	if registration == nil {
		if registration, err = c.Register(ctx, metadata.AuthorizationServers[0], name, []string{loopback.RedirectURI()}, scopes...); err != nil {
			return nil, err
		}
	}

	// Authorize it, and wait for its callback
	authorization, err := c.Authorize(metadata, *registration, loopback.RedirectURI(), scopes...)
	if err != nil {
		return nil, err
	}
	if err := open(authorization.URL); err != nil {
		return nil, err
	}
	query, err := loopback.Wait(ctx)
	if err != nil {
		return nil, errors.Join(goauth.ErrBadParameter.With("it wasn't authorized"), err)
	}
	return c.Exchange(ctx, authorization, query)
}
