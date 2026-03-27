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

package webcallback

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	// Packages
	"github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// Result contains the callback outcome passed back from the HTTP handler.
type Result struct {
	Query url.Values `json:"result,omitempty"`
	Err   error      `json:"err,omitempty"`
}

// webCallback serves a loopback HTTP callback URL and captures the first
// callback request.
type webCallback struct {
	url      *url.URL
	listener net.Listener
}

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

const (
	defaultResponseHTML = "<html><body><p>Authentication complete. You can return to the CLI.</p></body></html>"
	readHeaderTimeout   = 5 * time.Second
	shutdownTimeout     = time.Second
)

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// New validates the supplied loopback callback URL, opens the
// listener immediately, and stores the resolved callback URL. The URL must use
// the http scheme and a loopback hostname such as 127.0.0.1, localhost, or
// ::1. The port may be omitted or set to 0 to allocate a free port.
func New(url string) (*webCallback, error) {
	callbackURL, err := parseCallbackURL(url)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", callbackURL.Host)
	if err != nil {
		return nil, err
	}
	return &webCallback{
		url:      resolvedCallbackURL(callbackURL, listener.Addr()),
		listener: listener,
	}, nil
}

///////////////////////////////////////////////////////////////////////////////
// STRINGIFY

func (r *Result) String() string {
	return types.Stringify(r)
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - RESULT

// Code returns the OAuth authorization code from the callback query.
func (r Result) Code() string {
	return r.Query.Get("code")
}

// State returns the OAuth state parameter from the callback query.
func (r Result) State() string {
	return r.Query.Get("state")
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - CALLBACK

// URL returns the resolved callback URL.
func (w *webCallback) URL() string {
	return w.url.String()
}

// Run serves the callback listener and blocks until the first callback is
// received or the context is cancelled. The listener is closed before Run
// returns.
func (w *webCallback) Run(ctx context.Context) (*Result, error) {
	defer w.listener.Close()

	// Create a channel to receive the callback result
	results := make(chan Result, 1)

	// Create an HTTP server with a handler that captures the callback query
	server := &http.Server{
		Handler:           callbackMux(w.url, results),
		ReadHeaderTimeout: readHeaderTimeout,
	}
	defer shutdownServer(server)

	// Start the server and wait for the result or context cancellation
	go serveCallback(server, w.listener, results)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-results:
		if errors.Is(result.Err, net.ErrClosed) {
			return nil, nil
		}
		return &result, result.Err
	}
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func parseCallbackURL(rawURL string) (*url.URL, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, fmt.Errorf("callback URL is required")
	}
	uri, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if uri.Scheme != "http" {
		return nil, fmt.Errorf("callback URL must use http")
	}
	hostname := strings.TrimSpace(uri.Hostname())
	if hostname == "" {
		return nil, fmt.Errorf("callback URL host is required")
	}
	if !isLoopbackHost(hostname) {
		return nil, fmt.Errorf("callback URL host %q must be loopback", hostname)
	}
	if uri.Port() == "" {
		uri.Host = joinHostPort(hostname, "0")
	}
	if uri.Path == "" {
		uri.Path = "/"
	}
	uri.RawQuery = ""
	uri.Fragment = ""
	return uri, nil
}

func joinHostPort(host, port string) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return net.JoinHostPort(host, port)
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}

func resolvedCallbackURL(base *url.URL, addr net.Addr) *url.URL {
	resolved := *base
	if tcp, ok := addr.(*net.TCPAddr); ok {
		hostname := base.Hostname()
		resolved.Host = joinHostPort(hostname, fmt.Sprint(tcp.Port))
	}
	return &resolved
}

func callbackMux(callbackURL *url.URL, results chan<- Result) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(callbackURL.EscapedPath(), func(rw http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			rw.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		query := r.URL.Query()
		writeResponse(rw)
		sendResult(results, Result{Query: query, Err: callbackError(query)})
	})
	return mux
}

func serveCallback(server *http.Server, listener net.Listener, results chan<- Result) {
	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		sendResult(results, Result{Err: err})
	}
}

func shutdownServer(server *http.Server) {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)
}

func sendResult(results chan<- Result, result Result) {
	select {
	case results <- result:
	default:
	}
}

func callbackError(values url.Values) error {
	code := strings.TrimSpace(values.Get("error"))
	if code == "" {
		return nil
	}
	description := strings.TrimSpace(values.Get("error_description"))
	if description == "" {
		return fmt.Errorf("%s", code)
	}
	return fmt.Errorf("%s: %s", code, description)
}

func writeResponse(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(defaultResponseHTML))
}
