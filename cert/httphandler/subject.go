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
	"strconv"

	// Packages
	cert "github.com/mutablelogic/go-auth/cert/cert"
	manager "github.com/mutablelogic/go-auth/cert/manager"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	httprouter "github.com/mutablelogic/go-server/pkg/httprouter"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
	opts "github.com/mutablelogic/go-server/pkg/openapi"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// subjectParams is the path parameter of a subject
type subjectParams struct {
	ID uint64 `json:"id" help:"Subject identifier"`
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS - PATHS

// registerSubject registers listing and creating subjects, and getting,
// updating and deleting one, which no certificate uses
func registerSubject(router *httprouter.Router, mgr *manager.Manager, auth bool, doc *opts.MarkdownDoc) error {
	return errors.Join(
		router.Register("subject", nil, func(path httprequest.PathItem) {
			path.Tag(tagSubject)
			path.Get(func(w http.ResponseWriter, r *http.Request) {
				listSubjects(mgr, w, r)
			}, func(op httprequest.PathOperation) {
				op.Summary("List subjects")
				op.Description(doc.Section(3, "GET /subject").Body)
				op.Query(jsonschema.MustFor[cert.SubjectListRequest]())
				op.JSONResponse(http.StatusOK, jsonschema.MustFor[cert.SubjectList](), "Subjects, with the number of certificates which use each")
				op.ErrorResponse(http.StatusBadRequest, "Invalid pagination parameters")
				security(op, auth, cert.ScopeCertRead)
			})
			path.Post(func(w http.ResponseWriter, r *http.Request) {
				createSubject(mgr, w, r)
			}, func(op httprequest.PathOperation) {
				op.Summary("Create a subject")
				op.Description(doc.Section(3, "POST /subject").Body)
				op.RequestBody(jsonschema.MustFor[cert.SubjectMeta]())
				op.JSONResponse(http.StatusCreated, jsonschema.MustFor[cert.Subject](), "The subject, or an identical one which is stored")
				op.ErrorResponse(http.StatusBadRequest, "Invalid request body, or a subject without fields")
				security(op, auth, cert.ScopeCertWrite)
			})
		}),
		router.Register("subject/{id}", jsonschema.MustFor[subjectParams](), func(path httprequest.PathItem) {
			path.Tag(tagSubject)
			path.Get(func(w http.ResponseWriter, r *http.Request) {
				getSubject(mgr, w, r)
			}, func(op httprequest.PathOperation) {
				op.Summary("Get a subject")
				op.Description(doc.Section(3, "GET /subject/{id}").Body)
				op.JSONResponse(http.StatusOK, jsonschema.MustFor[cert.Subject](), "The subject, with the number of certificates which use it")
				op.ErrorResponse(http.StatusBadRequest, "Invalid identifier")
				op.ErrorResponse(http.StatusNotFound, "Subject not found")
				security(op, auth, cert.ScopeCertRead)
			})
			path.Patch(func(w http.ResponseWriter, r *http.Request) {
				updateSubject(mgr, w, r)
			}, func(op httprequest.PathOperation) {
				op.Summary("Update a subject")
				op.Description(doc.Section(3, "PATCH /subject/{id}").Body)
				op.RequestBody(jsonschema.MustFor[cert.SubjectMeta]())
				op.JSONResponse(http.StatusOK, jsonschema.MustFor[cert.Subject](), "The subject")
				op.ErrorResponse(http.StatusBadRequest, "Invalid identifier or request body, or nothing to update")
				op.ErrorResponse(http.StatusNotFound, "Subject not found")
				op.ErrorResponse(http.StatusConflict, "Certificates use the subject")
				security(op, auth, cert.ScopeCertWrite)
			})
			path.Delete(func(w http.ResponseWriter, r *http.Request) {
				deleteSubject(mgr, w, r)
			}, func(op httprequest.PathOperation) {
				op.Summary("Delete a subject")
				op.Description(doc.Section(3, "DELETE /subject/{id}").Body)
				op.EmptyResponse("Deleted")
				op.ErrorResponse(http.StatusBadRequest, "Invalid identifier")
				op.ErrorResponse(http.StatusNotFound, "Subject not found")
				op.ErrorResponse(http.StatusConflict, "Certificates use the subject")
				security(op, auth, cert.ScopeCertWrite)
			})
		}),
	)
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS - HANDLERS

func listSubjects(mgr *manager.Manager, w http.ResponseWriter, r *http.Request) {
	var req cert.SubjectListRequest
	if err := httprequest.Query(r.URL.Query(), &req); err != nil {
		httpresponse.Error(w, httpresponse.ErrBadRequest.Withf("%v", err))
		return
	}
	subjects, err := mgr.ListSubjects(r.Context(), req)
	if err != nil {
		httpresponse.Error(w, httpErr(err))
		return
	}
	httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), subjects)
}

func createSubject(mgr *manager.Manager, w http.ResponseWriter, r *http.Request) {
	var req cert.SubjectMeta
	if err := httprequest.Read(r, &req); err != nil {
		httpresponse.Error(w, httpresponse.ErrBadRequest.Withf("%v", err))
		return
	}
	subject, err := mgr.CreateSubject(r.Context(), req)
	if err != nil {
		httpresponse.Error(w, httpErr(err))
		return
	}
	httpresponse.JSON(w, http.StatusCreated, httprequest.Indent(r), subject)
}

func getSubject(mgr *manager.Manager, w http.ResponseWriter, r *http.Request) {
	id, err := subjectID(r)
	if err != nil {
		httpresponse.Error(w, err)
		return
	}
	subject, err := mgr.GetSubject(r.Context(), id)
	if err != nil {
		httpresponse.Error(w, httpErr(err))
		return
	}
	httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), subject)
}

func updateSubject(mgr *manager.Manager, w http.ResponseWriter, r *http.Request) {
	id, err := subjectID(r)
	if err != nil {
		httpresponse.Error(w, err)
		return
	}
	var req cert.SubjectMeta
	if err := httprequest.Read(r, &req); err != nil {
		httpresponse.Error(w, httpresponse.ErrBadRequest.Withf("%v", err))
		return
	}
	subject, err := mgr.UpdateSubject(r.Context(), id, req)
	if err != nil {
		httpresponse.Error(w, httpErr(err))
		return
	}
	httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), subject)
}

func deleteSubject(mgr *manager.Manager, w http.ResponseWriter, r *http.Request) {
	id, err := subjectID(r)
	if err != nil {
		httpresponse.Error(w, err)
		return
	}
	if _, err := mgr.DeleteSubject(r.Context(), id); err != nil {
		httpresponse.Error(w, httpErr(err))
		return
	}
	httpresponse.Empty(w, http.StatusNoContent)
}

// subjectID is the subject's identifier in the path, which is positive, and
// 32 bits
func subjectID(r *http.Request) (uint64, error) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 31)
	if err != nil || id == 0 {
		return 0, httpresponse.ErrBadRequest.Withf("subject identifier %q is invalid", r.PathValue("id"))
	}
	return id, nil
}
