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

package schema

import (
	"encoding/base64"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	ldap "github.com/go-ldap/ldap/v3"
	pg "github.com/mutablelogic/go-pg"
	types "github.com/mutablelogic/go-server/pkg/types"
)

//////////////////////////////////////////////////////////////////////////////////
// TYPES

type Object struct {
	DN         string `json:"dn"`
	url.Values `json:"attrs,omitempty"`
}

type PasswordResponse struct {
	Object
	GeneratedPassword string `json:"generated-password,omitempty"`
}

type ObjectPutRequest struct {
	Attrs url.Values `json:"attrs"`
}

type ObjectPasswordRequest struct {
	Old string  `json:"old,omitempty"`
	New *string `json:"new,omitempty"`
}

type ObjectListRequest struct {
	pg.OffsetLimit
	Filter *string  `json:"filter,omitempty" help:"Filter"`
	Attr   []string `json:"attr,omitempty" help:"Attributes to return"`
}

type ObjectList struct {
	Count uint64    `json:"count"`
	Body  []*Object `json:"body,omitempty"`
}

var (
	ldapAttributeDescriptorPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]*$`)
	ldapAttributeOIDPattern        = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)+$`)
	ldapAttributeOptionPattern     = regexp.MustCompile(`^[A-Za-z0-9-]+$`)
)

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func NewObject(v ...string) *Object {
	o := new(Object)
	o.DN = strings.Join(v, ",")
	o.Values = url.Values{}
	return o
}

func NewObjectFromEntry(entry *ldap.Entry) *Object {
	o := NewObject(entry.DN)
	for _, attr := range entry.Attributes {
		o.Values[attr.Name] = attr.Values
	}
	return o
}

///////////////////////////////////////////////////////////////////////////////
// STRINGIFY

func (o Object) String() string {
	return types.Stringify(o)
}

func (o PasswordResponse) String() string {
	return types.Stringify(o)
}

func (o ObjectPutRequest) String() string {
	return types.Stringify(o)
}

func (o ObjectPasswordRequest) String() string {
	return types.Stringify(o)
}

func (o ObjectList) String() string {
	return types.Stringify(o)
}

func (o ObjectListRequest) String() string {
	return types.Stringify(o)
}

///////////////////////////////////////////////////////////////////////////////
// LDIF FORMAT

func (o Object) LDIF() string {
	var result strings.Builder
	writeLDIFLine(&result, "dn", o.DN)

	keys := make([]string, 0, len(o.Values))
	for key := range o.Values {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		values := o.Values[key]
		if len(values) == 0 {
			result.WriteString(key)
			result.WriteString(":\n")
			continue
		}
		for _, value := range values {
			writeLDIFLine(&result, key, value)
		}
	}

	return result.String()
}

func (o PasswordResponse) LDIF() string {
	var result strings.Builder
	if strings.TrimSpace(o.GeneratedPassword) != "" {
		writeLDIFCommentLine(&result, "generated-password", o.GeneratedPassword)
	}
	result.WriteString(Object{DN: o.DN, Values: o.Values}.LDIF())
	return result.String()
}

func (o ObjectList) LDIF() string {
	entries := make([]string, 0, len(o.Body))
	for _, object := range o.Body {
		if object != nil {
			entries = append(entries, object.LDIF())
		}
	}
	var result strings.Builder
	result.WriteString("# objects: ")
	result.WriteString(strconv.Itoa(len(entries)))
	result.WriteByte('\n')
	result.WriteString("version: 1\n")
	if len(entries) > 0 {
		result.WriteByte('\n')
		result.WriteString(strings.Join(entries, "\n"))
	}
	return result.String()
}

func writeLDIFLine(result *strings.Builder, attr, value string) {
	if needsBase64Encoding(value) {
		result.WriteString(attr)
		result.WriteString(":: ")
		result.WriteString(base64.StdEncoding.EncodeToString([]byte(value)))
		result.WriteByte('\n')
		return
	}
	result.WriteString(attr)
	result.WriteString(": ")
	result.WriteString(value)
	result.WriteByte('\n')
}

func writeLDIFCommentLine(result *strings.Builder, attr, value string) {
	if needsBase64Encoding(value) {
		result.WriteString("# ")
		result.WriteString(attr)
		result.WriteString(":: ")
		result.WriteString(base64.StdEncoding.EncodeToString([]byte(value)))
		result.WriteByte('\n')
		return
	}
	result.WriteString("# ")
	result.WriteString(attr)
	result.WriteString(": ")
	result.WriteString(value)
	result.WriteByte('\n')
}

func needsBase64Encoding(value string) bool {
	if value == "" {
		return false
	}
	if strings.HasPrefix(value, " ") || strings.HasPrefix(value, ":") || strings.HasPrefix(value, "<") || strings.HasSuffix(value, " ") {
		return true
	}
	for _, r := range value {
		if r == 0 || r == '\n' || r == '\r' {
			return true
		}
		if r > 127 || !utf8.ValidRune(r) {
			return true
		}
	}
	return false
}

///////////////////////////////////////////////////////////////////////////////
// QUERY

func (req ObjectPutRequest) ValidateCreate() (url.Values, error) {
	return normalizeObjectAttrs(req.Attrs, true)
}

func (req ObjectPutRequest) ValidateUpdate() (url.Values, error) {
	return normalizeObjectAttrs(req.Attrs, false)
}

func (req ObjectListRequest) Query() url.Values {
	values := url.Values{}
	if req.Offset > 0 {
		values.Set("offset", strconv.FormatUint(req.Offset, 10))
	}
	if req.Limit != nil {
		values.Set("limit", strconv.FormatUint(types.Value(req.Limit), 10))
	}
	if req.Filter != nil {
		values.Set("filter", *req.Filter)
	}
	for _, attr := range req.Attr {
		values.Add("attr", attr)
	}
	return values
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// WithPassword embeds a generated password into the response object using the
// PasswordResponse wrapper. An empty password leaves the password field unset.
func (o *Object) WithPassword(password *string) *PasswordResponse {
	response := &PasswordResponse{}
	if o == nil || password == nil || strings.TrimSpace(*password) == "" {
		if o != nil {
			response.Object = *o
		}
		return response
	}
	response.Object = *o
	response.GeneratedPassword = *password
	return response
}

// Returns an attribute value or nil if not found
func (o *Object) Get(attr string) *string {
	values := o.GetAll(attr)
	if values == nil {
		return nil
	} else if len(values) == 0 {
		return types.Ptr("")
	} else {
		return types.Ptr(values[0])
	}
}

// Returns array or attributes or nil if not found
func (o *Object) GetAll(attr string) []string {
	// Try case insensitive
	if values, ok := o.Values[attr]; ok {
		return values
	}
	// Try case insensitive
	for k, values := range o.Values {
		if strings.EqualFold(k, attr) {
			return values
		}
	}
	// Not found
	return nil
}

func normalizeObjectAttrs(attrs url.Values, requireObjectClass bool) (url.Values, error) {
	if len(attrs) == 0 {
		return nil, auth.ErrBadParameter.With("attrs is required")
	}

	result := make(url.Values, len(attrs))
	for key, values := range attrs {
		key = strings.TrimSpace(key)
		if key == "" {
			return nil, auth.ErrBadParameter.With("attribute name is required")
		}
		if !isValidAttributeDescription(key) {
			return nil, auth.ErrBadParameter.Withf("invalid attribute name %q", key)
		}
		if strings.EqualFold(key, "dn") {
			return nil, auth.ErrBadParameter.With("dn must be provided in the path, not attrs")
		}

		normalized := make([]string, 0, len(values))
		for _, value := range values {
			value = strings.TrimSpace(value)
			if value != "" {
				normalized = append(normalized, value)
			}
		}

		if requireObjectClass && len(normalized) == 0 {
			return nil, auth.ErrBadParameter.Withf("attribute %q requires at least one value", key)
		}

		result[key] = normalized
	}

	if requireObjectClass {
		if values := result["objectClass"]; len(values) == 0 {
			if values := result["objectclass"]; len(values) == 0 {
				return nil, auth.ErrBadParameter.With("attrs.objectClass is required")
			}
		}
	}

	return result, nil
}

func isValidAttributeDescription(value string) bool {
	parts := strings.Split(value, ";")
	if len(parts) == 0 {
		return false
	}
	base := parts[0]
	if !ldapAttributeDescriptorPattern.MatchString(base) && !ldapAttributeOIDPattern.MatchString(base) {
		return false
	}
	for _, option := range parts[1:] {
		if !ldapAttributeOptionPattern.MatchString(option) {
			return false
		}
	}
	return true
}
