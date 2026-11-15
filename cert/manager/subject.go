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

package manager

import (
	"context"
	"errors"

	// Packages
	cert "github.com/mutablelogic/go-auth/cert/cert"
	schema "github.com/mutablelogic/go-auth/cert/schema"
	otel "github.com/mutablelogic/go-client/pkg/otel"
	pg "github.com/mutablelogic/go-pg"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	types "github.com/mutablelogic/go-server/pkg/types"
	attribute "go.opentelemetry.io/otel/attribute"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// ListSubjects returns a page of the subjects, in the order they were
// created, with the number of certificates which use each
func (m *Manager) ListSubjects(ctx context.Context, req cert.SubjectListRequest) (_ *cert.SubjectList, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "certmanager.ListSubjects", attribute.String("request", req.String()))
	defer func() { endSpan(err) }()

	result := cert.SubjectList{SubjectListRequest: req}
	if err = m.PoolConn.List(ctx, (*schema.SubjectList)(&result), schema.SubjectListRequest(req)); err != nil {
		return nil, err
	}
	return types.Ptr(result), nil
}

// GetSubject returns a subject, with the number of certificates which use it
func (m *Manager) GetSubject(ctx context.Context, id uint64) (_ *cert.Subject, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "certmanager.GetSubject", attribute.Int64("id", int64(id)))
	defer func() { endSpan(err) }()

	var result cert.Subject
	if err = m.Get(ctx, (*schema.Subject)(&result), schema.SubjectID(id)); err != nil {
		return nil, err
	}
	return types.Ptr(result), nil
}

// CreateSubject stores a subject, which certificates can then be created
// with, or returns an identical one, when it's stored. It needs a field.
func (m *Manager) CreateSubject(ctx context.Context, meta cert.SubjectMeta) (_ *cert.Subject, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "certmanager.CreateSubject", attribute.String("meta", meta.String()))
	defer func() { endSpan(err) }()

	if meta = cert.MergeSubjectMeta(meta, nil); meta == (cert.SubjectMeta{}) {
		return nil, httpresponse.ErrBadRequest.With("subject has no fields")
	}
	var result cert.Subject
	if err = m.Insert(ctx, (*schema.Subject)(&result), schema.SubjectMeta(meta)); err != nil {
		return nil, err
	}
	return types.Ptr(result), nil
}

// UpdateSubject changes the fields of a subject which no certificate uses,
// as a certificate's subject is in the certificate, which it would no
// longer be. A field which isn't set is kept, and an empty one removed.
func (m *Manager) UpdateSubject(ctx context.Context, id uint64, meta cert.SubjectMeta) (_ *cert.Subject, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "certmanager.UpdateSubject",
		attribute.Int64("id", int64(id)),
		attribute.String("meta", meta.String()),
	)
	defer func() { endSpan(err) }()

	var result cert.Subject
	if err = m.Update(ctx, (*schema.Subject)(&result), schema.SubjectID(id), schema.SubjectMeta(meta)); errors.Is(err, pg.ErrNotFound) {
		return nil, m.subjectNotChanged(ctx, id)
	} else if err != nil {
		return nil, err
	}
	return types.Ptr(result), nil
}

// DeleteSubject deletes a subject which no certificate uses, as deleting it
// would delete its certificates
func (m *Manager) DeleteSubject(ctx context.Context, id uint64) (_ *cert.Subject, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "certmanager.DeleteSubject", attribute.Int64("id", int64(id)))
	defer func() { endSpan(err) }()

	var result cert.Subject
	if err = m.Delete(ctx, (*schema.Subject)(&result), schema.SubjectID(id)); errors.Is(err, pg.ErrNotFound) {
		return nil, m.subjectNotChanged(ctx, id)
	} else if err != nil {
		return nil, err
	}
	return types.Ptr(result), nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// subjectNotChanged is why a subject wasn't updated or deleted: it's used by
// certificates, which is a conflict, or it's not found
func (m *Manager) subjectNotChanged(ctx context.Context, id uint64) error {
	subject, err := m.GetSubject(ctx, id)
	if err != nil {
		return err
	}
	return httpresponse.ErrConflict.Withf("subject %d is used by %d certificates", id, subject.Certs)
}
