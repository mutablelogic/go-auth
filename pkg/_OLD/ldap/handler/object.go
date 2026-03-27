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

package handler

import (
	"net/http"

	// Packages
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	ldap "github.com/mutablelogic/go-server/pkg/ldap"
	schema "github.com/mutablelogic/go-server/pkg/ldap/schema"
)

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func objectList(w http.ResponseWriter, r *http.Request, manager *ldap.Manager) error {
	// Parse request
	var req schema.ObjectListRequest
	if err := httprequest.Query(r.URL.Query(), &req); err != nil {
		return httpresponse.Error(w, err)
	}

	// List the objects
	response, err := manager.List(r.Context(), req)
	if err != nil {
		return httpresponse.Error(w, err)
	}

	// Return success
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), response)
}

func objectCreate(w http.ResponseWriter, r *http.Request, manager *ldap.Manager) error {
	// Parse request
	var req schema.Object
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, err)
	}

	// Create the object
	response, err := manager.Create(r.Context(), req.DN, req.Values)
	if err != nil {
		return httpresponse.Error(w, err)
	}

	// Return success
	return httpresponse.JSON(w, http.StatusCreated, httprequest.Indent(r), response)
}

func objectGet(w http.ResponseWriter, r *http.Request, manager *ldap.Manager, dn string) error {
	// Get the object
	response, err := manager.Get(r.Context(), dn)
	if err != nil {
		return httpresponse.Error(w, err)
	}

	// Return success
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), response)
}

func objectDelete(w http.ResponseWriter, r *http.Request, manager *ldap.Manager, dn string) error {
	// Delete the object
	_, err := manager.Delete(r.Context(), dn)
	if err != nil {
		return httpresponse.Error(w, err)
	}

	// Return success
	return httpresponse.Empty(w, http.StatusOK)
}

func objectUpdate(w http.ResponseWriter, r *http.Request, manager *ldap.Manager, dn string) error {
	// Parse request
	var req schema.Object
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, err)
	}

	// Update the attributes
	// TODO: Need to support adding and removing attributes, and changing the DN
	response, err := manager.Update(r.Context(), dn, req.Values)
	if err != nil {
		return httpresponse.Error(w, err)
	}

	// Return success
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), response)
}
