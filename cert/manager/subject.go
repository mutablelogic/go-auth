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
	"math"
	"strconv"

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

	// The limit is at most the query's, so the response says which subjects
	// it has, and the next page starts after them
	req.OffsetLimit = clampLimit(req.OffsetLimit, schema.SubjectListLimit)
	result := cert.SubjectList{SubjectListRequest: req}
	if err = m.PoolConn.List(ctx, (*schema.SubjectList)(&result), schema.SubjectListRequest(req)); err != nil {
		return nil, err
	}
	return types.Ptr(result), nil
}

// GetSubject returns a subject, with the number of certificates which use it
func (m *Manager) GetSubject(ctx context.Context, id uint64) (_ *cert.Subject, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "certmanager.GetSubject", attribute.String("id", strconv.FormatUint(id, 10)))
	defer func() { endSpan(err) }()

	if err := validID(id); err != nil {
		return nil, err
	}
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
		attribute.String("id", strconv.FormatUint(id, 10)),
		attribute.String("meta", meta.String()),
	)
	defer func() { endSpan(err) }()

	var result cert.Subject
	if err = m.unused(ctx, id, func(conn pg.Conn) error {
		return conn.Update(ctx, (*schema.Subject)(&result), schema.SubjectID(id), schema.SubjectMeta(meta))
	}); err != nil {
		return nil, err
	}
	return types.Ptr(result), nil
}

// DeleteSubject deletes a subject which no certificate uses, as deleting it
// would delete its certificates
func (m *Manager) DeleteSubject(ctx context.Context, id uint64) (_ *cert.Subject, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "certmanager.DeleteSubject", attribute.String("id", strconv.FormatUint(id, 10)))
	defer func() { endSpan(err) }()

	var result cert.Subject
	if err = m.unused(ctx, id, func(conn pg.Conn) error {
		return conn.Delete(ctx, (*schema.Subject)(&result), schema.SubjectID(id))
	}); err != nil {
		return nil, err
	}
	return types.Ptr(result), nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// unused calls fn, in a transaction, when no certificate uses the subject,
// or else returns a conflict, or not found. The subject is locked first,
// which waits for a certificate which is being created with it, which locks
// it too, so it's counted, in a statement after the lock, and stops another
// from being created with it until fn's change is committed.
func (m *Manager) unused(ctx context.Context, id uint64, fn func(pg.Conn) error) error {
	if err := validID(id); err != nil {
		return err
	}
	return m.Tx(ctx, func(conn pg.Conn) error {
		var locked, subject cert.Subject
		if err := conn.Get(ctx, (*schema.Subject)(&locked), schema.SubjectLock(id)); err != nil {
			return err
		}
		if err := conn.Get(ctx, (*schema.Subject)(&subject), schema.SubjectID(id)); err != nil {
			return err
		} else if subject.Certs > 0 {
			return httpresponse.ErrConflict.Withf("subject %d is used by %d certificates", id, subject.Certs)
		}
		return fn(conn)
	})
}

// validID is an error when the identifier isn't a subject's, which are
// positive, and 32 bits
func validID(id uint64) error {
	if id == 0 || id > math.MaxInt32 {
		return httpresponse.ErrBadRequest.Withf("subject identifier %d is invalid", id)
	}
	return nil
}

// clampLimit is the request's limit, at most the query's maximum. A limit
// which isn't set is the query's default, and stays unset.
func clampLimit(offsetlimit cert.OffsetLimit, max uint64) cert.OffsetLimit {
	if offsetlimit.Limit != nil && *offsetlimit.Limit > max {
		offsetlimit.Limit = types.Ptr(max)
	}
	return offsetlimit
}
