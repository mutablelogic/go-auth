package manager

import (
	"context"

	// Packages
	schema "github.com/djthorpe/go-auth/schema"
	otel "github.com/mutablelogic/go-client/pkg/otel"
	types "github.com/mutablelogic/go-server/pkg/types"
	attribute "go.opentelemetry.io/otel/attribute"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (m *Manager) ListScopes(ctx context.Context, req schema.ScopeListRequest) (_ *schema.ScopeList, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "manager.ListScopes", attribute.String("request", req.String()))
	defer func() { endSpan(err) }()

	result := schema.ScopeList{OffsetLimit: req.OffsetLimit}
	if err = m.PoolConn.List(ctx, &result, req); err != nil {
		err = dbErr(err)
		return nil, err
	}
	return types.Ptr(result), nil
}
