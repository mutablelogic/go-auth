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
	ldapparser "github.com/mutablelogic/go-auth/pkg/ldapparser"
	schemadef "github.com/mutablelogic/go-auth/schema/ldapparser"
	pg "github.com/mutablelogic/go-pg"
	types "github.com/mutablelogic/go-server/pkg/types"
)

//////////////////////////////////////////////////////////////////////////////////
// TYPES

type AttributeType struct {
	*schemadef.AttributeTypeSchema
}

type AttributeUsage string

type AttributeTypeListRequest struct {
	pg.OffsetLimit
	Filter             *string         `json:"filter,omitempty" help:"Exact attribute name or OID match (case-insensitive for names)" arg:"" optional:""`
	Usage              *AttributeUsage `json:"usage,omitempty" help:"Attribute usage" enum:"userApplications,directoryOperation,distributedOperation,dSAOperation"`
	Superior           *string         `json:"superior,omitempty" help:"Exact superior attribute type match"`
	Obsolete           *bool           `json:"obsolete,omitempty" help:"Filter obsolete attribute types"`
	SingleValue        *bool           `json:"singleValue,omitempty" help:"Filter single-value attribute types" name:"single-value"`
	Collective         *bool           `json:"collective,omitempty" help:"Filter collective attribute types"`
	NoUserModification *bool           `json:"noUserModification,omitempty" help:"Filter non-user-modifiable attribute types" name:"no-user-modification"`
}

type AttributeTypeListResponse struct {
	Count uint64           `json:"count" help:"Total number of matching attribute types before pagination"`
	Body  []*AttributeType `json:"body,omitempty" help:"Attribute types returned for the current page"`
}

//////////////////////////////////////////////////////////////////////////////////
// GLOBALS

const (
	AttributeUsageUserApplications     AttributeUsage = AttributeUsage(schemadef.AttributeUsageUserApplications)
	AttributeUsageDirectoryOperation   AttributeUsage = AttributeUsage(schemadef.AttributeUsageDirectoryOperation)
	AttributeUsageDistributedOperation AttributeUsage = AttributeUsage(schemadef.AttributeUsageDistributedOperation)
	AttributeUsageDSAOperation         AttributeUsage = AttributeUsage(schemadef.AttributeUsageDSAOperation)
)

//////////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func ParseAttributeType(v string) (*AttributeType, error) {
	schema, err := ldapparser.New(v).ParseAttributeType()
	if err != nil {
		return nil, err
	}
	return &AttributeType{schema}, nil
}

//////////////////////////////////////////////////////////////////////////////////
// STRINGIFY

func (o AttributeType) String() string {
	return types.Stringify(o)
}

func (o AttributeUsage) String() string {
	return string(o)
}

func (o AttributeTypeListRequest) String() string {
	return types.Stringify(o)
}

func (o AttributeTypeListResponse) String() string {
	return types.Stringify(o)
}

//////////////////////////////////////////////////////////////////////////////////
// QUERY

func (req AttributeTypeListRequest) Query() url.Values {
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
	if req.Usage != nil {
		values.Set("usage", req.Usage.String())
	}
	if req.Superior != nil {
		values.Set("superior", *req.Superior)
	}
	if req.Obsolete != nil {
		values.Set("obsolete", strconv.FormatBool(*req.Obsolete))
	}
	if req.SingleValue != nil {
		values.Set("singleValue", strconv.FormatBool(*req.SingleValue))
	}
	if req.Collective != nil {
		values.Set("collective", strconv.FormatBool(*req.Collective))
	}
	if req.NoUserModification != nil {
		values.Set("noUserModification", strconv.FormatBool(*req.NoUserModification))
	}
	return values
}

//////////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (o *AttributeType) Matches(req AttributeTypeListRequest) bool {
	if o == nil || o.AttributeTypeSchema == nil {
		return false
	}
	if req.Filter != nil && !attributeTypeContains(o, *req.Filter) {
		return false
	}
	if req.Usage != nil && !strings.EqualFold(strings.TrimSpace(req.Usage.String()), string(o.Usage)) {
		return false
	}
	if req.Superior != nil && !strings.EqualFold(strings.TrimSpace(*req.Superior), strings.TrimSpace(o.SuperType)) {
		return false
	}
	if req.Obsolete != nil && o.Obsolete != *req.Obsolete {
		return false
	}
	if req.SingleValue != nil && o.SingleValue != *req.SingleValue {
		return false
	}
	if req.Collective != nil && o.Collective != *req.Collective {
		return false
	}
	if req.NoUserModification != nil && o.NoUserModification != *req.NoUserModification {
		return false
	}
	return true
}

func (o *AttributeType) Identifier() string {
	if o == nil || o.AttributeTypeSchema == nil {
		return ""
	}
	if len(o.Name) > 0 {
		return o.Name[0]
	}
	return o.NumericOID
}

func attributeTypeContains(o *AttributeType, value string) bool {
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
