package schema

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	// Packages
	auth "github.com/djthorpe/go-auth"
	uuid "github.com/google/uuid"
	pg "github.com/mutablelogic/go-pg"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func Test_identity_schema_001(t *testing.T) {
	t.Run("NewIdentityFromClaims", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		claims := map[string]any{
			"iss":   "https://issuer.example.com",
			"sub":   "subject-1",
			"email": "alice@example.com",
		}
		identity, err := NewIdentityFromClaims(claims)
		require.NoError(err)
		assert.Equal("https://issuer.example.com", identity.Provider)
		assert.Equal("subject-1", identity.Sub)
		assert.Equal("alice@example.com", identity.Email)
		assert.Equal(claims, identity.Claims)

		identity, err = NewIdentityFromClaims(map[string]any{
			"iss":   "https://issuer.example.com",
			"sub":   "subject-2",
			"email": "Alice Example <ALICE@example.com>",
		})
		require.NoError(err)
		assert.Equal("alice@example.com", identity.Email)

		_, err = NewIdentityFromClaims(map[string]any{"sub": "subject-1"})
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrBadParameter)

		_, err = NewIdentityFromClaims(map[string]any{"iss": "https://issuer.example.com"})
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrBadParameter)
	})

	t.Run("IdentityInsertName", func(t *testing.T) {
		assert := assert.New(t)

		assert.Equal("Alice", IdentityInsert{IdentityMeta: IdentityMeta{Email: "alice@example.com", Claims: map[string]any{"name": " Alice "}}}.Name())
		assert.Equal("alice-user", IdentityInsert{IdentityMeta: IdentityMeta{Email: "alice@example.com", Claims: map[string]any{"preferred_username": "alice-user"}}}.Name())
		assert.Equal("alice@example.com", IdentityInsert{IdentityMeta: IdentityMeta{Email: " alice@example.com "}}.Name())
		assert.Equal("Alice Example", IdentityInsert{IdentityMeta: IdentityMeta{Email: "Alice Example <alice@example.com>"}}.Name())
	})

	t.Run("IdentityKeySelect", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		key := IdentityKey{Provider: " github ", Sub: " alice "}

		bind := pg.NewBind("schema", DefaultSchema)
		query, err := key.Select(bind, pg.Get)
		require.NoError(err)
		assert.NotEmpty(query)
		assert.Equal("github", bind.Get("provider"))
		assert.Equal("alice", bind.Get("sub"))

		bind = pg.NewBind("schema", DefaultSchema)
		_, err = key.Select(bind, pg.Update)
		require.NoError(err)

		bind = pg.NewBind("schema", DefaultSchema)
		_, err = key.Select(bind, pg.Delete)
		require.NoError(err)

		_, err = (IdentityKey{}).Select(pg.NewBind(), pg.Get)
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrBadParameter)

		_, err = (IdentityKey{Provider: "github"}).Select(pg.NewBind(), pg.Get)
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrBadParameter)

		_, err = key.Select(pg.NewBind(), pg.None)
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrNotImplemented)
	})

	t.Run("IdentityListRequestSelect", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		user := uuid.New()
		limit := uint64(250)
		bind := pg.NewBind("schema", DefaultSchema)
		query, err := (IdentityListRequest{
			OffsetLimit: pg.OffsetLimit{Offset: 3, Limit: &limit},
			User:        &user,
		}).Select(bind, pg.List)
		require.NoError(err)
		assert.NotEmpty(query)
		assert.Equal(`WHERE identity."user" = @user`, bind.Get("where"))
		assert.Equal(`ORDER BY identity.provider ASC, identity.sub ASC`, bind.Get("orderby"))

		bind = pg.NewBind("schema", DefaultSchema)
		query, err = (IdentityListRequest{}).Select(bind, pg.List)
		require.NoError(err)
		assert.NotEmpty(query)
		assert.Equal("", bind.Get("where"))

		_, err = (IdentityListRequest{}).Select(pg.NewBind(), pg.Get)
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrNotImplemented)
	})

	t.Run("IdentityScan", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		userID := UserID(uuid.New())
		createdAt := time.Now().UTC().Add(-time.Hour)
		modifiedAt := time.Now().UTC()
		claims := map[string]any{"role": "admin"}

		var identity Identity
		err := identity.Scan(mockRow{values: []any{
			userID,
			"github",
			"alice",
			"alice@example.com",
			claims,
			createdAt,
			modifiedAt,
		}})
		require.NoError(err)
		assert.Equal(userID, identity.User)
		assert.Equal("github", identity.Provider)
		assert.Equal("alice", identity.Sub)
		assert.Equal("alice@example.com", identity.Email)
		assert.Equal(claims, identity.Claims)
		assert.Equal(createdAt, identity.CreatedAt)
		assert.Equal(modifiedAt, identity.ModifiedAt)
	})

	t.Run("IdentityListScanAndCount", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		userID := UserID(uuid.New())
		list := IdentityList{OffsetLimit: pg.OffsetLimit{Limit: ptrUint64(10)}}
		require.NoError(list.Scan(mockRow{values: []any{
			userID,
			"github",
			"alice",
			"alice@example.com",
			map[string]any{"role": "admin"},
			time.Now().UTC().Add(-time.Hour),
			time.Now().UTC(),
		}}))
		assert.Len(list.Body, 1)

		require.NoError(list.ScanCount(mockRow{values: []any{uint(2)}}))
		assert.Equal(uint(2), list.Count)
		require.NotNil(list.Limit)
		assert.Equal(uint64(2), *list.Limit)
	})

	t.Run("IdentityMetaInsertAndUpdate", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		meta := IdentityMeta{Email: " USER@EXAMPLE.COM ", Claims: map[string]any{"role": "admin"}}
		bind := pg.NewBind("schema", DefaultSchema)
		bind.Set("user", UserID(uuid.New()))
		bind.Set("provider", "github")
		bind.Set("sub", "alice")
		query, err := meta.Insert(bind)
		require.NoError(err)
		assert.NotEmpty(query)
		assert.Equal("user@example.com", bind.Get("email"))
		claimsJSON, ok := bind.Get("claims").(string)
		require.True(ok)
		var claims map[string]any
		require.NoError(json.Unmarshal([]byte(claimsJSON), &claims))
		assert.Equal("admin", claims["role"])

		patchBind := pg.NewBind()
		require.NoError(meta.Update(patchBind))
		patch, ok := patchBind.Get("patch").(string)
		require.True(ok)
		assert.Contains(patch, "email = ")
		assert.Contains(patch, "claims = ")
	})

	t.Run("IdentityInsertValidation", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		bind := pg.NewBind("schema", DefaultSchema)
		bind.Set("user", UserID(uuid.New()))
		query, err := (IdentityInsert{
			IdentityKey:  IdentityKey{Provider: " github ", Sub: " alice "},
			IdentityMeta: IdentityMeta{Email: "alice@example.com"},
		}).Insert(bind)
		require.NoError(err)
		assert.NotEmpty(query)
		assert.Equal("github", bind.Get("provider"))
		assert.Equal("alice", bind.Get("sub"))

		_, err = (IdentityInsert{}).Insert(pg.NewBind())
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrBadParameter)

		_, err = (IdentityInsert{IdentityKey: IdentityKey{Provider: "github"}}).Insert(pg.NewBind())
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrBadParameter)
	})

	t.Run("IdentityMetaValidationErrors", func(t *testing.T) {
		assert := assert.New(t)

		_, err := (IdentityMeta{}).Insert(pg.NewBind())
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrBadParameter)

		bind := pg.NewBind()
		bind.Set("user", UserID(uuid.New()))
		_, err = (IdentityMeta{}).Insert(bind)
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrBadParameter)

		bind = pg.NewBind()
		bind.Set("user", UserID(uuid.New()))
		bind.Set("provider", "github")
		_, err = (IdentityMeta{}).Insert(bind)
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrBadParameter)

		err = (IdentityMeta{}).Update(pg.NewBind())
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrBadParameter)
	})
}

type mockRow struct {
	values []any
	err    error
}

func (row mockRow) Scan(dest ...any) error {
	if row.err != nil {
		return row.err
	}
	if len(dest) != len(row.values) {
		return fmt.Errorf("expected %d destinations, got %d", len(row.values), len(dest))
	}
	for index, value := range row.values {
		target := reflect.ValueOf(dest[index])
		if target.Kind() != reflect.Ptr || target.IsNil() {
			return fmt.Errorf("destination %d is not a pointer", index)
		}
		if value == nil {
			target.Elem().Set(reflect.Zero(target.Elem().Type()))
			continue
		}
		source := reflect.ValueOf(value)
		if source.Type().AssignableTo(target.Elem().Type()) {
			target.Elem().Set(source)
			continue
		}
		if source.Type().ConvertibleTo(target.Elem().Type()) {
			target.Elem().Set(source.Convert(target.Elem().Type()))
			continue
		}
		return fmt.Errorf("cannot assign %T to %T", value, dest[index])
	}
	return nil
}

func ptrUint64(value uint64) *uint64 {
	return &value
}
