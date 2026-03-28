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

package ldap

import (
	"net/url"
	"strings"
)

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// containsFold reports whether s appears in values with case-insensitive comparison.
func containsFold(values []string, s string) bool {
	for _, v := range values {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

func attrHas(attrs url.Values, name string) bool {
	_, ok := attrKey(attrs, name)
	return ok
}

func attrValues(attrs url.Values, name string) []string {
	if key, ok := attrKey(attrs, name); ok {
		return attrs[key]
	}
	return nil
}

func attrSet(attrs url.Values, name string, values []string) {
	if key, ok := attrKey(attrs, name); ok {
		attrs[key] = values
	} else {
		attrs[name] = values
	}
}

func attrKey(attrs url.Values, name string) (string, bool) {
	for key := range attrs {
		if strings.EqualFold(key, name) {
			return key, true
		}
	}
	return "", false
}
