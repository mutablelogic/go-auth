package schema

import (
	"encoding/json"
	"fmt"
	"sort"

	// Packages
	auth "github.com/djthorpe/go-auth"
	pg "github.com/mutablelogic/go-pg"
	types "github.com/mutablelogic/go-server/pkg/types"
)

func metaKeys(values map[string]any) ([]string, error) {
	keys := make([]string, 0, len(values))
	for key := range values {
		if !types.IsIdentifier(key) {
			return nil, auth.ErrBadParameter.Withf("invalid meta key %q", key)
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys, nil
}

// metaInsertExpr returns a sanitized JSON object for INSERT statements.
// Only keys that are valid identifiers and values that are non-nil are copied.
func metaInsertExpr(values map[string]any) (map[string]any, error) {
	keys, err := metaKeys(values)
	if err != nil {
		return nil, err
	}
	result := make(map[string]any, len(keys))
	for _, key := range keys {
		if values[key] != nil {
			result[key] = values[key]
		}
	}
	return result, nil
}

// metaPatchExpr returns a SQL expression that applies top-level JSONB
// key updates to an existing column value. Nil values delete keys; non-nil
// values upsert keys.
func metaPatchExpr(bind *pg.Bind, column string, paramPrefix string, values map[string]any) (string, error) {
	keys, err := metaKeys(values)
	if err != nil {
		return "", err
	}

	expr := "COALESCE(" + types.DoubleQuote(column) + ", '{}'::jsonb)"
	for index, key := range keys {
		keyRef := bind.Set(fmt.Sprintf("%s_key_%d", paramPrefix, index), key)
		if values[key] == nil {
			expr = "(" + expr + " - " + keyRef + "::text)"
			continue
		}
		value, err := json.Marshal(values[key])
		if err != nil {
			return "", err
		}
		valueRef := bind.Set(fmt.Sprintf("%s_value_%d", paramPrefix, index), string(value))
		expr = "(" + expr + " || jsonb_build_object(" + keyRef + "::text, " + valueRef + "::jsonb))"
	}

	return expr, nil
}
