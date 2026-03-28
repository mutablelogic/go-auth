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
	"net/url"
	"strconv"
	"strings"

	// Packages
	pg "github.com/mutablelogic/go-pg"
	types "github.com/mutablelogic/go-server/pkg/types"
	parser "github.com/yinyin/go-ldap-schema-parser"
)

//////////////////////////////////////////////////////////////////////////////////
// TYPES

type ObjectClass struct {
	*parser.ObjectClassSchema
}

type ObjectClassKind string

const (
	ObjectClassKindAbstract   ObjectClassKind = ObjectClassKind(parser.ClassKindAbstract)
	ObjectClassKindStructural ObjectClassKind = ObjectClassKind(parser.ClassKindStructural)
	ObjectClassKindAuxiliary  ObjectClassKind = ObjectClassKind(parser.ClassKindAuxiliary)
)

type ObjectClassListRequest struct {
	pg.OffsetLimit
	Filter   *string          `json:"filter,omitempty" help:"Exact class name or OID match (case-insensitive for names)" arg:"" optional:""`
	Kind     *ObjectClassKind `json:"kind,omitempty" help:"Class kind" enum:"ABSTRACT,STRUCTURAL,AUXILIARY"`
	Superior []string         `json:"superior,omitempty" help:"Required superior classes"`
	Must     []string         `json:"must,omitempty" help:"Required MUST attributes"`
	May      []string         `json:"may,omitempty" help:"Required MAY attributes"`
	Obsolete *bool            `json:"obsolete,omitempty" help:"Filter obsolete classes"`
}

type ObjectClassListResponse struct {
	Count uint64         `json:"count"`
	Body  []*ObjectClass `json:"body,omitempty"`
}

//////////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func ParseObjectClass(v string) (*ObjectClass, error) {
	if !hasNumericOIDPrefix(v) {
		return nil, errUnsupportedSchemaDefinition
	}
	schema, err := parser.ParseObjectClassSchema(v)
	if err != nil {
		return nil, err
	}
	return types.Ptr(ObjectClass{schema}), nil
}

//////////////////////////////////////////////////////////////////////////////////
// STRINGIFY

func (o ObjectClass) String() string {
	return types.Stringify(o)
}

func (o ObjectClassKind) String() string {
	return string(o)
}

func (o ObjectClassListRequest) String() string {
	return types.Stringify(o)
}

func (o ObjectClassListResponse) String() string {
	return types.Stringify(o)
}

//////////////////////////////////////////////////////////////////////////////////
// QUERY

func (req ObjectClassListRequest) Query() url.Values {
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
	if req.Kind != nil {
		values.Set("kind", req.Kind.String())
	}
	for _, value := range req.Superior {
		values.Add("superior", value)
	}
	for _, value := range req.Must {
		values.Add("must", value)
	}
	for _, value := range req.May {
		values.Add("may", value)
	}
	if req.Obsolete != nil {
		values.Set("obsolete", strconv.FormatBool(*req.Obsolete))
	}
	return values
}

//////////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (o *ObjectClass) Matches(req ObjectClassListRequest) bool {
	if o == nil || o.ObjectClassSchema == nil {
		return false
	}
	if req.Filter != nil && !objectClassContains(o, *req.Filter) {
		return false
	}
	if req.Kind != nil && !strings.EqualFold(strings.TrimSpace(req.Kind.String()), o.ClassKind) {
		return false
	}
	if req.Obsolete != nil && o.Obsolete != *req.Obsolete {
		return false
	}
	if !containsAllFold(o.SuperClasses, req.Superior) {
		return false
	}
	if !containsAllFold(o.Must, req.Must) {
		return false
	}
	if !containsAllFold(o.May, req.May) {
		return false
	}
	return true
}

func (o *ObjectClass) Identifier() string {
	if o == nil || o.ObjectClassSchema == nil {
		return ""
	}
	if len(o.Name) > 0 {
		return o.Name[0]
	}
	return o.NumericOID
}

func objectClassContains(o *ObjectClass, value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return true
	}
	if o.NumericOID == value {
		return true
	}
	for _, name := range o.Name {
		if strings.EqualFold(strings.TrimSpace(name), value) {
			return true
		}
	}
	return false
}

func containsAllFold(values, required []string) bool {
	for _, want := range required {
		want = strings.TrimSpace(want)
		if want == "" {
			continue
		}
		matched := false
		for _, have := range values {
			if strings.EqualFold(strings.TrimSpace(have), want) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}
