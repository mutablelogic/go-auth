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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	schema "github.com/mutablelogic/go-auth/ldap/schema"
	pg "github.com/mutablelogic/go-pg"
	require "github.com/stretchr/testify/require"
)

func TestListObjectClassesUsesQueryParameters(t *testing.T) {
	require := require.New(t)
	filter := "person"
	kind := schema.ObjectClassKindStructural
	obsolete := false
	limit := uint64(25)
	req := schema.ObjectClassListRequest{
		OffsetLimit: pg.OffsetLimit{Offset: 10, Limit: &limit},
		Filter:      &filter,
		Kind:        &kind,
		Superior:    []string{"top"},
		Must:        []string{"cn"},
		May:         []string{"mail"},
		Obsolete:    &obsolete,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(http.MethodGet, r.Method)
		require.Equal("/class", r.URL.Path)
		require.Equal("10", r.URL.Query().Get("offset"))
		require.Equal("25", r.URL.Query().Get("limit"))
		require.Equal("person", r.URL.Query().Get("filter"))
		require.Equal("STRUCTURAL", r.URL.Query().Get("kind"))
		require.Equal([]string{"top"}, r.URL.Query()["superior"])
		require.Equal([]string{"cn"}, r.URL.Query()["must"])
		require.Equal([]string{"mail"}, r.URL.Query()["may"])
		require.Equal("false", r.URL.Query().Get("obsolete"))
		w.Header().Set("Content-Type", "application/json")
		require.NoError(json.NewEncoder(w).Encode(schema.ObjectClassListResponse{Count: 1, Body: []*schema.ObjectClass{}}))
	}))
	defer server.Close()

	client, err := New(server.URL)
	require.NoError(err)
	response, err := client.ListObjectClasses(context.Background(), req)
	require.NoError(err)
	require.NotNil(response)
	require.Equal(uint64(1), response.Count)
	require.Empty(response.Body)
}

func TestListAttributeTypesUsesQueryParameters(t *testing.T) {
	require := require.New(t)
	filter := "cn"
	usage := schema.AttributeUsageUserApplications
	obsolete := false
	singleValue := true
	limit := uint64(10)
	req := schema.AttributeTypeListRequest{
		OffsetLimit: pg.OffsetLimit{Offset: 5, Limit: &limit},
		Filter:      &filter,
		Usage:       &usage,
		Superior:    nil,
		Obsolete:    &obsolete,
		SingleValue: &singleValue,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(http.MethodGet, r.Method)
		require.Equal("/attr", r.URL.Path)
		require.Equal("5", r.URL.Query().Get("offset"))
		require.Equal("10", r.URL.Query().Get("limit"))
		require.Equal("cn", r.URL.Query().Get("filter"))
		require.Equal("userApplications", r.URL.Query().Get("usage"))
		require.Equal("false", r.URL.Query().Get("obsolete"))
		require.Equal("true", r.URL.Query().Get("singleValue"))
		w.Header().Set("Content-Type", "application/json")
		require.NoError(json.NewEncoder(w).Encode(schema.AttributeTypeListResponse{Count: 1, Body: []*schema.AttributeType{}}))
	}))
	defer server.Close()

	client, err := New(server.URL)
	require.NoError(err)
	response, err := client.ListAttributeTypes(context.Background(), req)
	require.NoError(err)
	require.NotNil(response)
	require.Equal(uint64(1), response.Count)
	require.Empty(response.Body)
}
