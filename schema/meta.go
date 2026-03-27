package schema

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	// Packages
	auth "github.com/djthorpe/go-auth"
	pg "github.com/mutablelogic/go-pg"
	types "github.com/mutablelogic/go-server/pkg/types"
)

type MetaMap map[string]any

func (meta *MetaMap) UnmarshalJSON(data []byte) error {
	if raw := strings.TrimSpace(string(data)); raw == "" || raw == "null" {
		*meta = nil
		return nil
	}

	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	if _, err := metaKeys(value); err != nil {
		return err
	}
	*meta = MetaMap(value)
	return nil
}

func (meta *MetaMap) UnmarshalText(text []byte) error {
	raw := strings.TrimSpace(string(text))
	if raw == "" {
		*meta = nil
		return nil
	}

	parsed, err := parseMetaMap(raw)
	if err != nil {
		return err
	}

	*meta = MetaMap(parsed)
	return nil
}

func (meta MetaMap) String() string {
	return types.Stringify(meta)
}

func (meta MetaMap) RedactedString() string {
	r := make(MetaMap, len(meta))
	for k, v := range meta {
		r[k] = v
	}
	for _, key := range []string{"name", "email"} {
		if _, ok := r[key]; ok {
			r[key] = "[redacted]"
		}
	}
	return types.Stringify(r)
}

func (meta MetaMap) Map() map[string]any {
	if len(meta) == 0 {
		return nil
	}
	result := make(map[string]any, len(meta))
	for key, value := range meta {
		result[key] = value
	}
	return result
}

func (meta *MetaMap) Scan(src any) error {
	switch src := src.(type) {
	case nil:
		*meta = nil
		return nil
	case []byte:
		return meta.UnmarshalJSON(src)
	case string:
		return meta.UnmarshalJSON([]byte(src))
	case map[string]any:
		if _, err := metaKeys(src); err != nil {
			return err
		}
		*meta = MetaMap(src)
		return nil
	default:
		return fmt.Errorf("scan MetaMap: unsupported type %T", src)
	}
}

func (meta MetaMap) Value() (driver.Value, error) {
	if meta == nil {
		return nil, nil
	}
	return json.Marshal(meta.Map())
}

func parseMetaMap(raw string) (map[string]any, error) {
	if strings.HasPrefix(raw, "{") {
		var meta map[string]any
		if err := json.Unmarshal([]byte(raw), &meta); err != nil {
			return nil, fmt.Errorf("parse meta JSON: %w", err)
		}
		if _, err := metaKeys(meta); err != nil {
			return nil, err
		}
		return meta, nil
	}

	meta := make(map[string]any)
	for _, field := range splitMetaFields(raw) {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			return nil, auth.ErrBadParameter.Withf("invalid meta entry %q", field)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if !types.IsIdentifier(key) {
			return nil, auth.ErrBadParameter.Withf("invalid meta key %q", key)
		}
		meta[key] = parseMetaValue(value)
	}

	if len(meta) == 0 {
		return nil, nil
	}
	return meta, nil
}

func splitMetaFields(raw string) []string {
	fields := make([]string, 0, 1)
	start := 0
	depth := 0
	inString := false
	escaped := false

	for index, r := range raw {
		switch {
		case escaped:
			escaped = false
		case r == '\\' && inString:
			escaped = true
		case r == '"':
			inString = !inString
		case !inString && (r == '{' || r == '['):
			depth++
		case !inString && (r == '}' || r == ']') && depth > 0:
			depth--
		case !inString && depth == 0 && (r == ';' || r == ','):
			fields = append(fields, raw[start:index])
			start = index + 1
		}
	}

	fields = append(fields, raw[start:])
	return fields
}

func parseMetaValue(raw string) any {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	var value any
	if err := json.Unmarshal([]byte(raw), &value); err == nil {
		return value
	}

	return raw
}

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
