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
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	schema "github.com/mutablelogic/go-auth/schema/ldap"
	require "github.com/stretchr/testify/require"
)

func TestUpdateObjectUsesPatch(t *testing.T) {
	require := require.New(t)
	dn := "cn=test,ou=users,dc=example,dc=com"
	request := schema.ObjectPutRequest{Attrs: url.Values{"description": {"updated"}}}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body schema.ObjectPutRequest
		require.Equal(http.MethodPatch, r.Method)
		require.Equal("/object/"+dn, r.URL.Path)
		require.NoError(json.NewDecoder(r.Body).Decode(&body))
		w.Header().Set("Content-Type", "application/json")
		require.NoError(json.NewEncoder(w).Encode(schema.Object{DN: dn, Values: body.Attrs}))
	}))
	defer server.Close()

	client, err := New(server.URL)
	require.NoError(err)
	response, err := client.UpdateObject(context.Background(), dn, request)
	require.NoError(err)
	require.NotNil(response)
	require.Equal(dn, response.DN)
	require.Equal([]string{"updated"}, response.Values["description"])
}

func TestBindObjectUsesPlainTextPost(t *testing.T) {
	require := require.New(t)
	dn := "cn=test,ou=users,dc=example,dc=com"
	password := "secret"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(err)
		require.Equal(http.MethodPost, r.Method)
		require.Equal("/object/"+dn+"/bind", r.URL.Path)
		require.Equal("text/plain", r.Header.Get("Content-Type"))
		require.Equal(password, string(body))
		w.Header().Set("Content-Type", "application/json")
		require.NoError(json.NewEncoder(w).Encode(schema.Object{DN: dn}))
	}))
	defer server.Close()

	client, err := New(server.URL)
	require.NoError(err)
	response, err := client.BindObject(context.Background(), dn, password)
	require.NoError(err)
	require.NotNil(response)
	require.Equal(dn, response.DN)
}

func TestChangeObjectPasswordUsesJSONPost(t *testing.T) {
	require := require.New(t)
	dn := "cn=test,ou=users,dc=example,dc=com"
	newPassword := "new-secret"
	request := schema.ObjectPasswordRequest{Old: "old-secret", New: &newPassword}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body schema.ObjectPasswordRequest
		require.Equal(http.MethodPost, r.Method)
		require.Equal("/object/"+dn+"/password", r.URL.Path)
		require.NoError(json.NewDecoder(r.Body).Decode(&body))
		w.Header().Set("Content-Type", "application/json")
		require.NoError(json.NewEncoder(w).Encode(schema.PasswordResponse{
			Object:            schema.Object{DN: dn},
			GeneratedPassword: newPassword,
		}))
	}))
	defer server.Close()

	client, err := New(server.URL)
	require.NoError(err)
	response, err := client.ChangeObjectPassword(context.Background(), dn, request)
	require.NoError(err)
	require.NotNil(response)
	require.Equal(dn, response.DN)
	require.Equal(newPassword, response.GeneratedPassword)
}

func TestDeleteObjectReturnsDeletedObject(t *testing.T) {
	require := require.New(t)
	dn := "cn=test,ou=users,dc=example,dc=com"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(http.MethodDelete, r.Method)
		require.Equal("/object/"+dn, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		require.NoError(json.NewEncoder(w).Encode(schema.Object{DN: dn}))
	}))
	defer server.Close()

	client, err := New(server.URL)
	require.NoError(err)
	object, err := client.DeleteObject(context.Background(), dn)
	require.NoError(err)
	require.NotNil(object)
	require.Equal(dn, object.DN)
}
