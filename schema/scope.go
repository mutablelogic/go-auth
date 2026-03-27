package schema

import (
	"net/url"
	"strconv"
	"strings"

	// Packages
	auth "github.com/djthorpe/go-auth"
	pg "github.com/mutablelogic/go-pg"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type ScopeListRequest struct {
	pg.OffsetLimit
	Q string `json:"q,omitempty"`
}

type ScopeList struct {
	pg.OffsetLimit
	Count uint     `json:"count" readonly:""`
	Body  []string `json:"body,omitempty"`
}

///////////////////////////////////////////////////////////////////////////////
// STRINGIFY

func (req ScopeListRequest) Query() url.Values {
	values := url.Values{}
	if req.Offset > 0 {
		values.Set("offset", strconv.FormatUint(req.Offset, 10))
	}
	if req.Limit != nil {
		values.Set("limit", strconv.FormatUint(types.Value(req.Limit), 10))
	}
	if q := strings.TrimSpace(req.Q); q != "" {
		values.Set("q", q)
	}
	return values
}

func (list ScopeList) String() string {
	return types.Stringify(list)
}

func (req ScopeListRequest) String() string {
	return types.Stringify(req)
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - SELECTOR

func (req ScopeListRequest) Select(bind *pg.Bind, op pg.Op) (string, error) {
	bind.Del("where")
	if q := strings.TrimSpace(req.Q); q != "" {
		bind.Append("where", "scope LIKE "+bind.Set("q", "%"+escapeLikePattern(q)+"%")+` ESCAPE E'\\'`)
	}
	if where := bind.Join("where", " AND "); where == "" {
		bind.Set("where", "WHERE scope IS NOT NULL")
	} else {
		bind.Set("where", "WHERE scope IS NOT NULL AND "+where)
	}
	bind.Set("orderby", "ORDER BY scope ASC")
	req.OffsetLimit.Bind(bind, ScopeListMax)

	switch op {
	case pg.List:
		return bind.Query("scope.list"), nil
	default:
		return "", auth.ErrNotImplemented.Withf("unsupported ScopeListRequest operation %q", op)
	}
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - READER

func (list *ScopeList) Scan(row pg.Row) error {
	var scope string
	if err := row.Scan(&scope); err != nil {
		return err
	}
	list.Body = append(list.Body, scope)
	return nil
}

func (list *ScopeList) ScanCount(row pg.Row) error {
	if err := row.Scan(&list.Count); err != nil {
		return err
	}
	list.Clamp(uint64(list.Count))
	return nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func normalizeScopes(scopes []string) []string {
	result := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if scope = strings.TrimSpace(scope); scope != "" {
			result = append(result, scope)
		}
	}
	return result
}

func escapeLikePattern(value string) string {
	replacer := strings.NewReplacer(
		`\\`, `\\\\`,
		`%`, `\\%`,
		`_`, `\\_`,
	)
	return replacer.Replace(value)
}
