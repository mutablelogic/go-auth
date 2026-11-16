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
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	// Packages
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// AuthError is a server's challenge, as a request to it isn't authorized:
// its scheme, such as Bearer, and its parameters, by their names in lower
// case, such as realm, and resource_metadata, the URL of the resource's
// metadata
type AuthError struct {
	Scheme string     `json:"scheme"`
	Params url.Values `json:"params,omitempty"`
}

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

// AuthenticateHeader is the header of a server's challenges
const AuthenticateHeader = "WWW-Authenticate"

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// ParseChallenge returns the challenge of the header, of its challenges,
// which is the Bearer one, when it has one, as that's the scheme a token
// is for, or otherwise its first, or nil, when it hasn't any
func ParseChallenge(header http.Header) *AuthError {
	var challenges []*AuthError
	for _, value := range header.Values(AuthenticateHeader) {
		challenges = append(challenges, parseChallenges(value)...)
	}
	if len(challenges) == 0 {
		return nil
	}
	for _, challenge := range challenges {
		if strings.EqualFold(challenge.Scheme, "Bearer") {
			return challenge
		}
	}
	return challenges[0]
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// AsAuthError returns the AuthError the error is, or wraps, or nil
func AsAuthError(err error) *AuthError {
	var authErr *AuthError
	if errors.As(err, &authErr) {
		return authErr
	}
	return nil
}

// Get returns the value of the challenge's parameter, whatever the case of
// its name, or nothing
func (e *AuthError) Get(key string) string {
	return e.Params.Get(strings.ToLower(key))
}

// Error returns the challenge's error, and its description, when it has
// them, or that it isn't authorized
func (e *AuthError) Error() string {
	code, description := e.Get("error"), e.Get("error_description")
	switch {
	case code != "" && description != "":
		return fmt.Sprintf("unauthorized: %s: %s", code, description)
	case description != "":
		return "unauthorized: " + description
	case code != "":
		return "unauthorized: " + code
	}
	return "unauthorized"
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE FUNCTIONS

// parseChallenges returns the challenges of a WWW-Authenticate header's
// value, each a scheme, and its parameters, which are name=value, or
// name="quoted value", separated by commas, until the next scheme, which
// is a token which isn't followed by =, outside a quoted value. A
// challenge's token68, such as Basic's, is skipped. Quoted values have
// their quoted pairs decoded, as HTTP has them: a backslash, and the
// character it's before, is the character.
// https://www.rfc-editor.org/rfc/rfc9110#section-11.6.1
func parseChallenges(value string) []*AuthError {
	p := &parser{s: value}
	var result []*AuthError
	var current *AuthError
	for {
		p.skip(" \t,")
		if p.done() {
			break
		}
		token := p.token()
		if token == "" {
			// Not a token, such as a stray quote, which is skipped
			p.i++
			continue
		}
		p.skip(" \t")
		if !p.done() && p.peek() == '=' && current != nil {
			// A parameter, or a token68 which ends with =, of the challenge
			p.i++
			p.skip(" \t")
			var param string
			if !p.done() && p.peek() == '"' {
				param = p.quoted()
			} else {
				param = p.token()
				for !p.done() && p.peek() == '=' {
					// The rest of a token68, such as abc==
					p.i++
				}
			}
			current.Params.Add(strings.ToLower(token), param)
			continue
		}
		// A scheme, which starts another challenge, followed by a token68,
		// or its parameters
		current = &AuthError{Scheme: token, Params: url.Values{}}
		result = append(result, current)
		p.skip(" \t")
		if !p.done() && p.peek() != ',' {
			mark := p.i
			candidate := p.token()
			p.skip(" \t")
			if candidate != "" && (p.done() || p.peek() == ',' || (p.peek() == '=' && p.equalsOnly())) {
				// A token68, such as Basic's
				for !p.done() && p.peek() == '=' {
					p.i++
				}
			} else {
				// A parameter, which the loop reads
				p.i = mark
			}
		}
	}
	return result
}

// parser reads a header's value
type parser struct {
	s string
	i int
}

func (p *parser) done() bool { return p.i >= len(p.s) }
func (p *parser) peek() byte { return p.s[p.i] }

// skip skips the characters which are any of those
func (p *parser) skip(chars string) {
	for !p.done() && strings.IndexByte(chars, p.peek()) >= 0 {
		p.i++
	}
}

// token reads a token, of the characters a token, or a token68, can have
func (p *parser) token() string {
	start := p.i
	for !p.done() && isTokenChar(p.peek()) {
		p.i++
	}
	return p.s[start:p.i]
}

// equalsOnly returns true when what's left, from the =, is only =, until
// the end, or a comma, as a token68's padding is, rather than a parameter
func (p *parser) equalsOnly() bool {
	j := p.i
	for j < len(p.s) && p.s[j] == '=' {
		j++
	}
	for j < len(p.s) && (p.s[j] == ' ' || p.s[j] == '\t') {
		j++
	}
	return j >= len(p.s) || p.s[j] == ','
}

// quoted reads a quoted value, with its quoted pairs decoded
func (p *parser) quoted() string {
	var b strings.Builder
	p.i++ // the opening quote
	for !p.done() {
		c := p.peek()
		p.i++
		switch {
		case c == '"':
			return b.String()
		case c == '\\' && !p.done():
			b.WriteByte(p.peek())
			p.i++
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// isTokenChar returns true when the character can be in a token, or a
// token68
func isTokenChar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("!#$%&'*+-.^_`|~/", c) >= 0
}

// httpStatus returns the HTTP status of an error, which a server returned,
// such as go-client's, when it has one
func httpStatus(err error) (int, bool) {
	if code, ok := errors.AsType[httpresponse.Err](err); ok {
		return int(code), true
	} else if response, ok := errors.AsType[httpresponse.ErrResponse](err); ok && response.Code != 0 {
		return response.Code, true
	}
	return 0, false
}
