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

package oidc

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type UserInfo struct {
	Subject string         `json:"id"`
	Name    string         `json:"name,omitempty"`
	Email   string         `json:"email,omitempty"`
	Claims  map[string]any `json:"claims,omitempty"`
}

///////////////////////////////////////////////////////////////////////////////
// STRINGIFY

func (u *UserInfo) String() string {
	return types.Stringify(u)
}

///////////////////////////////////////////////////////////////////////////////
// JSON MARSHAL/UNMARSHAL

/*
func (u *UserInfo) MarshalJSON() ([]byte, error) {
	if u == nil || u.Claims == nil || len(u.Claims) == 0 {
		return []byte("null"), nil
	} else {
		return json.Marshal(u.Claims)
	}
}
*/

func (u *UserInfo) UnmarshalJSON(data []byte) error {
	if u == nil {
		return fmt.Errorf("cannot unmarshal into nil UserInfo")
	}

	// Unmarshal the data into the claims map
	u.Claims = make(map[string]any)
	if err := json.Unmarshal(data, &u.Claims); err != nil {
		return err
	}

	// Sub is required
	sub, ok := u.Claims["sub"].(string)
	if !ok {
		return errors.New("Missing subject (sub) claim in userinfo response")
	} else if sub := strings.TrimSpace(sub); sub == "" {
		return errors.New("Missing subject (sub) claim in userinfo response")
	} else {
		u.Subject = strings.TrimSpace(sub)
	}

	// Name is optional
	if name, ok := u.Claims["name"].(string); ok {
		u.Name = strings.TrimSpace(name)
	}

	// Email is optional
	if email, ok := u.Claims["email"].(string); ok {
		u.Email = strings.TrimSpace(email)
	}

	return nil
}
