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

package auth

import (
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	// Packages
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type AuthError struct {
	Scheme     string `json:"scheme"`
	url.Values `json:"param,omitempty"`
}

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

const (
	ContentHeaderAuthenticate = "WWW-Authenticate"
)

var (
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/WWW-Authenticate
	reAuthChallengeExpr = regexp.MustCompile(`^\s*([^\s]+)\s*(.*)$`)
	reAuthParamExpr     = regexp.MustCompile(`([A-Za-z][A-Za-z0-9_-]*)\s*=\s*"((?:\\.|[^"\\])*)"`)
)

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func newAuthError(header http.Header) error {
	value := strings.TrimSpace(header.Get(ContentHeaderAuthenticate))
	if value == "" {
		return nil
	}

	// Parse the challenge
	match := reAuthChallengeExpr.FindStringSubmatch(value)
	if len(match) == 0 {
		return nil
	}
	scheme := strings.TrimSpace(match[1])
	remainder := strings.TrimSpace(match[2])
	if remainder == "" {
		return &AuthError{Scheme: scheme}
	}

	// Parse challenge parameters
	params := url.Values{}
	for _, token := range reAuthParamExpr.FindAllStringSubmatch(remainder, -1) {
		if len(token) != 3 {
			continue
		}
		value, err := strconv.Unquote(`"` + token[2] + `"`)
		if err != nil {
			value = token[2]
		}
		params.Add(token[1], value)
	}
	return &AuthError{Scheme: scheme, Values: params}
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (e *AuthError) String() string {
	return types.Stringify(e)
}

func (e *AuthError) Error() string {
	if e == nil {
		return ""
	}
	return e.String()
}
