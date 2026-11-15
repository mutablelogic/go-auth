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

package httphandler

import (
	"errors"
	"net/http"
	"strings"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	credential "github.com/mutablelogic/go-auth/credential"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	httprouter "github.com/mutablelogic/go-server/pkg/httprouter"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
	opts "github.com/mutablelogic/go-server/pkg/openapi"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// keyParams is the path parameter of a credential
type keyParams struct {
	Key string `json:"key" help:"Credential key"`
}

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

const (
	securityScheme = "bearerAuth"
)

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS - PATHS

// registerCredential registers listing, for a manager, and storing
// credentials
func registerCredential(router *httprouter.Router, provider credential.CredentialProvider, manager credential.CredentialManager, auth bool, doc *opts.MarkdownDoc) error {
	return router.Register("credential", nil, func(path httprequest.PathItem) {
		path.Tag(tag)
		if manager != nil {
			path.Get(func(w http.ResponseWriter, r *http.Request) {
				list(manager, w, r)
			}, func(op httprequest.PathOperation) {
				op.Summary("List credentials")
				op.Description(doc.Section(3, "GET /credential").Body)
				op.JSONResponse(http.StatusOK, jsonschema.MustFor[credential.CredentialList](), "Credentials, without their values")
				op.ErrorResponse(http.StatusForbidden, "The backend refused to list credentials")
				security(op, auth, credential.ScopeCredentialRead)
			})
		}
		path.Put(func(w http.ResponseWriter, r *http.Request) {
			set(provider, w, r)
		}, func(op httprequest.PathOperation) {
			op.Summary("Store a credential")
			op.Description(doc.Section(3, "PUT /credential").Body)
			op.RequestBody(jsonschema.MustFor[credential.CredentialSet]())
			op.JSONResponse(http.StatusOK, jsonschema.MustFor[credential.Credential](), "Stored credential")
			op.ErrorResponse(http.StatusBadRequest, "Invalid key, credentials or request body")
			op.ErrorResponse(http.StatusForbidden, "The backend refused the write")
			op.ErrorResponse(http.StatusNotImplemented, "The backend can't store credentials")
			op.ErrorResponse(http.StatusServiceUnavailable, "The backend has no passphrase")
			security(op, auth, credential.ScopeCredentialWrite)
		})
	})
}

// registerKey registers getting the metadata of, and deleting, a
// credential, for a manager, and getting its value with its passphrase, for
// a provider which encrypts with its own passphrases
func registerKey(router *httprouter.Router, provider credential.CredentialProvider, manager credential.CredentialManager, auth bool, doc *opts.MarkdownDoc) error {
	decrypter, canDecrypt := provider.(credential.CredentialDecrypter)
	if manager == nil && !canDecrypt {
		return nil
	}
	return router.Register("credential/{key}", jsonschema.MustFor[keyParams](), func(path httprequest.PathItem) {
		path.Tag(tag)
		if manager != nil {
			path.Get(func(w http.ResponseWriter, r *http.Request) {
				get(manager, w, r)
			}, func(op httprequest.PathOperation) {
				op.Summary("Get credential metadata")
				op.Description(doc.Section(3, "GET /credential/{key}").Body)
				op.JSONResponse(http.StatusOK, jsonschema.MustFor[credential.Credential](), "Credential key and the time it was last changed")
				op.ErrorResponse(http.StatusBadRequest, "Invalid key")
				op.ErrorResponse(http.StatusNotFound, "Credential not found")
				security(op, auth, credential.ScopeCredentialRead)
			})
		}
		if canDecrypt {
			path.Post(func(w http.ResponseWriter, r *http.Request) {
				decrypt(decrypter, w, r)
			}, func(op httprequest.PathOperation) {
				op.Summary("Get a credential's value")
				op.Description(doc.Section(3, "POST /credential/{key}").Body)
				op.RequestBody(jsonschema.MustFor[string](), types.ContentTypeTextPlain)
				op.JSONResponse(http.StatusOK, jsonschema.MustFor[any](), "Credential, which can be any JSON value")
				op.ErrorResponse(http.StatusBadRequest, "Invalid key or request body")
				op.ErrorResponse(http.StatusForbidden, "Invalid passphrase")
				op.ErrorResponse(http.StatusNotFound, "Credential not found")
				security(op, auth, credential.ScopeCredentialDecrypt)
			})
		}
		if manager != nil {
			path.Delete(func(w http.ResponseWriter, r *http.Request) {
				remove(manager, w, r)
			}, func(op httprequest.PathOperation) {
				op.Summary("Delete a credential")
				op.Description(doc.Section(3, "DELETE /credential/{key}").Body)
				op.EmptyResponse("Deleted")
				op.ErrorResponse(http.StatusBadRequest, "Invalid key")
				op.ErrorResponse(http.StatusNotFound, "Credential not found")
				security(op, auth, credential.ScopeCredentialWrite)
			})
		}
	})
}

// registerRotate registers rotating a credential, for a manager which
// encrypts with its own passphrases
func registerRotate(router *httprouter.Router, manager credential.CredentialManager, auth bool, doc *opts.MarkdownDoc) error {
	rotator, ok := manager.(credential.CredentialRotator)
	if manager == nil || !ok {
		return nil
	}
	return router.Register("credential/{key}/rotate", jsonschema.MustFor[keyParams](), func(path httprequest.PathItem) {
		path.Tag(tag)
		path.Post(func(w http.ResponseWriter, r *http.Request) {
			rotate(rotator, w, r)
		}, func(op httprequest.PathOperation) {
			op.Summary("Rotate a credential")
			op.Description(doc.Section(3, "POST /credential/{key}/rotate").Body)
			op.EmptyResponse("Rotated")
			op.Response(http.StatusNotModified, "", "The credential already uses the latest passphrase version")
			op.ErrorResponse(http.StatusBadRequest, "Invalid key")
			op.ErrorResponse(http.StatusNotFound, "Credential not found")
			op.ErrorResponse(http.StatusServiceUnavailable, "No passphrase is configured")
			security(op, auth, credential.ScopeCredentialWrite)
		})
	})
}

// security requires the bearer token scheme, with the scopes, when auth is
// true
func security(op httprequest.PathOperation, auth bool, scopes ...string) {
	if auth {
		op.Security(securityScheme, scopes...)
	}
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS - HANDLERS

func list(manager credential.CredentialManager, w http.ResponseWriter, r *http.Request) {
	result, err := manager.List(r.Context())
	if err != nil {
		httpresponse.Error(w, auth.HTTPError(err))
		return
	}
	httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), credential.CredentialList{Count: uint64(len(result)), Body: result})
}

func set(provider credential.CredentialProvider, w http.ResponseWriter, r *http.Request) {
	var req credential.CredentialSet
	if err := httprequest.Read(r, &req); err != nil {
		httpresponse.Error(w, httpresponse.ErrBadRequest.Withf("%v", err))
		return
	} else if len(req.Credentials) == 0 || string(req.Credentials) == "null" {
		httpresponse.Error(w, httpresponse.ErrBadRequest.With("credentials are required"))
		return
	}

	// A description needs a manager, which keeps them
	manager, describes := provider.(credential.CredentialManager)
	if req.Description != nil && !describes {
		httpresponse.Error(w, httpresponse.ErrNotImplemented.With("credentials have no descriptions"), req.Key)
		return
	}
	if err := provider.Set(r.Context(), req.Key, req.Credentials); err != nil {
		httpresponse.Error(w, auth.HTTPError(err), req.Key)
		return
	}
	result := credential.Credential{Key: req.Key}
	if req.Description != nil {
		if err := manager.Describe(r.Context(), req.Key, *req.Description); err != nil {
			httpresponse.Error(w, auth.HTTPError(err), req.Key)
			return
		}
		result.Description = strings.TrimSpace(*req.Description)
	}
	httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), result)
}

func get(manager credential.CredentialManager, w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if !types.IsIdentifier(key) {
		httpresponse.Error(w, httpresponse.ErrBadRequest.Withf("credential key %q must be an identifier", key))
		return
	}
	if result, err := find(r, manager, key); err != nil {
		httpresponse.Error(w, auth.HTTPError(err), key)
	} else {
		httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), result)
	}
}

func decrypt(decrypter credential.CredentialDecrypter, w http.ResponseWriter, r *http.Request) {
	// The value isn't cached, and nor is an error, which says whether the
	// passphrase is right
	w.Header().Set("Cache-Control", "no-store")
	key := r.PathValue("key")
	var passphrase string
	if err := httprequest.Read(r, &passphrase); err != nil {
		httpresponse.Error(w, httpresponse.ErrBadRequest.Withf("%v", err))
		return
	}
	value, err := decrypter.Decrypt(r.Context(), key, passphrase)
	if err != nil {
		httpresponse.Error(w, auth.HTTPError(err), key)
		return
	}
	httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), value)
}

func remove(manager credential.CredentialManager, w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if err := manager.Delete(r.Context(), key); err != nil {
		httpresponse.Error(w, auth.HTTPError(err), key)
	} else {
		httpresponse.Empty(w, http.StatusNoContent)
	}
}

func rotate(rotator credential.CredentialRotator, w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if err := rotator.Rotate(r.Context(), key); errors.Is(err, auth.ErrNotModified) {
		httpresponse.Empty(w, http.StatusNotModified)
	} else if err != nil {
		httpresponse.Error(w, auth.HTTPError(err), key)
	} else {
		httpresponse.Empty(w, http.StatusNoContent)
	}
}

// find returns the stored credential for the key, from the list, as the
// manager has no other way to get a credential without its value
func find(r *http.Request, manager credential.CredentialManager, key string) (*credential.Credential, error) {
	list, err := manager.List(r.Context())
	if err != nil {
		return nil, err
	}
	for _, c := range list {
		if c.Key == key {
			return &c, nil
		}
	}
	return nil, auth.ErrNotFound.Withf("credential %q not found", key)
}
