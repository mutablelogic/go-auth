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
	"testing"

	// Packages
	assert "github.com/stretchr/testify/assert"
)

func Test_WellKnown(t *testing.T) {
	// A well-known path is inserted between a URL's host and its path, then
	// after its path, and at its root
	assert.Equal(t, []string{
		"https://example.com/.well-known/oauth-protected-resource/v1/mcp",
		"https://example.com/v1/mcp/.well-known/oauth-protected-resource",
		"https://example.com/.well-known/oauth-protected-resource",
	}, wellKnown("https://example.com/v1/mcp?x=1", ResourceMetadataPath))
	assert.Equal(t, []string{
		"https://example.com/.well-known/oauth-protected-resource/mcp/",
		"https://example.com/mcp/.well-known/oauth-protected-resource",
		"https://example.com/.well-known/oauth-protected-resource",
	}, wellKnown("https://example.com/mcp/", ResourceMetadataPath), "with its slash")
	assert.Equal(t, []string{"https://example.com/.well-known/oauth-authorization-server"}, wellKnown("https://example.com/", OAuthMetadataPath))
	assert.Nil(t, wellKnown("not a url", OAuthMetadataPath))
	assert.Equal(t, "https://example.com:8443", origin("https://example.com:8443/mcp"))
	assert.Empty(t, origin("/mcp"))
}

func Test_SameResource(t *testing.T) {
	// The resource, apart from a slash at its end, its origin, or a parent
	for _, metadata := range []string{
		"https://example.com/v1/mcp",
		"https://example.com/v1/mcp/",
		"https://example.com/v1",
		"https://example.com",
		"https://example.com/",
		"HTTPS://EXAMPLE.COM/v1",
	} {
		assert.True(t, sameResource(metadata, "https://example.com/v1/mcp"), metadata)
	}
	assert.True(t, sameResource("https://example.com/mcp", "https://example.com/mcp/"))

	// Not another host, scheme, port, path or sibling, or a resource with a
	// query
	for _, metadata := range []string{
		"",
		"https://other.example.com/v1/mcp",
		"http://example.com/v1/mcp",
		"https://example.com:8443/v1/mcp",
		"https://example.com/v1/mcp/sub",
		"https://example.com/v1/mc",
		"https://example.com/v2",
		"https://example.com/v1?tenant=a",
		"https://user@example.com/v1",
		"/v1/mcp",
	} {
		assert.False(t, sameResource(metadata, "https://example.com/v1/mcp"), metadata)
	}
}
