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
	"encoding/json"
	"net/url"
	"strings"

	// Packages
	pg "github.com/djthorpe/go-pg"
	ldap "github.com/go-ldap/ldap/v3"
	"github.com/mutablelogic/go-server/pkg/types"
)

//////////////////////////////////////////////////////////////////////////////////
// TYPES

type Object struct {
	DN         string `json:"dn"`
	url.Values `json:"attrs,omitempty"`
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

func (o *Object) String() string {
	data, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return err.Error()
	}
	return string(data)
}

func (o *ObjectList) String() string {
	data, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return err.Error()
	}
	return string(data)
}

func (o *ObjectListRequest) String() string {
	data, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return err.Error()
	}
	return string(data)
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// Returns an attribute value or nil if not found
func (o *Object) Get(attr string) *string {
	values := o.GetAll(attr)
	if values == nil {
		return nil
	} else if len(values) == 0 {
		return types.StringPtr("")
	} else {
		return types.StringPtr(values[0])
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
