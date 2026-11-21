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

package httpclient_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	// Packages
	goauth "github.com/mutablelogic/go-auth"
	httpclient "github.com/mutablelogic/go-auth/auth/httpclient"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func Test_NewLoopbackAt(t *testing.T) {
	// Its redirect URI is of the host it's given, localhost, of its port,
	// so it can be one a web application's client registers
	l, err := httpclient.NewLoopbackAt("localhost:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	uri := l.RedirectURI()
	assert.True(t, strings.HasPrefix(uri, "http://localhost:"), uri)
	assert.True(t, strings.HasSuffix(uri, httpclient.CallbackPath), uri)

	// It's redirected to, of the code
	go func() {
		response, err := http.Get(uri + "?code=code&state=state")
		if err == nil {
			_ = response.Body.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	query, err := l.Wait(ctx)
	require.NoError(t, err)
	assert.Equal(t, "code", query.Get("code"))

	// Of an IP address, too
	ip, err := httpclient.NewLoopbackAt("127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ip.Close() })
	assert.True(t, strings.HasPrefix(ip.RedirectURI(), "http://127.0.0.1:"))

	// Not of another address, or one which isn't one
	for _, addr := range []string{"example.com:8085", "192.168.1.1:8085", "localhost", ""} {
		_, err := httpclient.NewLoopbackAt(addr)
		assert.ErrorIs(t, err, goauth.ErrBadParameter, addr)
	}
}
