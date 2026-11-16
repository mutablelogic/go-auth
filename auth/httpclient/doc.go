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

// Package httpclient is a general OAuth client, with go-client, which signs
// in to a resource which needs to be authorized, such as an MCP server's,
// or go-auth's own APIs:
//
//   - A request which isn't authorized returns an AuthError, with the
//     server's challenge.
//   - How a token is got is discovered: the resource's metadata (RFC 9728),
//     and that of its authorization servers (RFC 8414, or OpenID Connect).
//   - A client is registered (RFC 7591), or one is given.
//   - Authorize, and Exchange, are the authorization code grant, with PKCE's
//     S256, and a resource indicator (RFC 8707), and TokenSource refreshes
//     the grant's token.
//   - Login does it all, for a command, with a loopback callback (RFC 8252),
//     at a URL a browser opens.
package httpclient
