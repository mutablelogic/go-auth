package schema

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	// Packages
	auth "github.com/djthorpe/go-auth"
	uuid "github.com/google/uuid"
	pg "github.com/mutablelogic/go-pg"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func Test_user_001(t *testing.T) {
	t.Run("IsValidUserStatus", func(t *testing.T) {
		assert := assert.New(t)
		assert.True(IsValidUserStatus(UserStatusActive))
		assert.False(IsValidUserStatus(UserStatus("weird")))
	})

	t.Run("UserIDFromString", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		uid := uuid.New()
		id, err := UserIDFromString(uid.String())
		require.NoError(err)
		assert.Equal(UserID(uid), id)

		_, err = UserIDFromString(uuid.Nil.String())
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrBadParameter)
	})

	t.Run("UserIDJSON", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		uid := UserID(uuid.New())
		data, err := json.Marshal(uid)
		require.NoError(err)

		var roundtrip UserID
		require.NoError(json.Unmarshal(data, &roundtrip))
		assert.Equal(uid, roundtrip)

		err = json.Unmarshal([]byte(`"not-a-uuid"`), &roundtrip)
		assert.Error(err)

		err = json.Unmarshal([]byte(`"00000000-0000-0000-0000-000000000000"`), &roundtrip)
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrBadParameter)
	})

	t.Run("UserIDText", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		uid := uuid.New()
		var roundtrip UserID
		require.NoError(roundtrip.UnmarshalText([]byte(uid.String())))
		assert.Equal(UserID(uid), roundtrip)

		text, err := roundtrip.MarshalText()
		require.NoError(err)
		assert.Equal(uid.String(), string(text))

		err = roundtrip.UnmarshalText([]byte("not-a-uuid"))
		assert.Error(err)

		err = roundtrip.UnmarshalText([]byte(uuid.Nil.String()))
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrBadParameter)
	})

	t.Run("UserIDSelect", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		bind := pg.NewBind()
		uid := UserID(uuid.New())
		query, err := uid.Select(bind, pg.Get)
		require.NoError(err)
		assert.NotEmpty(query)
		assert.True(bind.Has("id"))

		_, err = uid.Select(pg.NewBind(), pg.Update)
		require.NoError(err)
		_, err = uid.Select(pg.NewBind(), pg.Delete)
		require.NoError(err)
		_, err = uid.Select(pg.NewBind(), pg.None)
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrNotImplemented)
	})

	t.Run("UserScan", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		userID := UserID(uuid.New())
		status := UserStatusActive
		createdAt := time.Now().UTC().Add(-time.Hour)
		expiresAt := time.Now().UTC().Add(time.Hour)
		modifiedAt := time.Now().UTC()
		meta := map[string]any{"team": "auth"}
		claims := map[string]any{"role": "admin"}

		var user User
		err := user.Scan(mockRow{values: []any{
			userID,
			"Test User",
			"user@example.com",
			meta,
			&status,
			createdAt,
			&expiresAt,
			&modifiedAt,
			claims,
			[]string{"staff"},
			[]string{"openid"},
		}})
		require.NoError(err)
		assert.Equal(userID, user.ID)
		assert.Equal("Test User", user.Name)
		assert.Equal("user@example.com", user.Email)
		assert.Equal(meta, user.Meta)
		require.NotNil(user.Status)
		assert.Equal(status, *user.Status)
		assert.Equal(createdAt, user.CreatedAt)
		require.NotNil(user.ExpiresAt)
		assert.Equal(expiresAt, *user.ExpiresAt)
		require.NotNil(user.ModifiedAt)
		assert.Equal(modifiedAt, *user.ModifiedAt)
		assert.Equal(claims, user.Claims)
		assert.Equal([]string{"staff"}, user.Groups)
		assert.Equal([]string{"openid"}, user.Scopes)
	})

	t.Run("UserListScanAndCount", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		userID := UserID(uuid.New())
		status := UserStatusActive
		createdAt := time.Now().UTC().Add(-time.Hour)
		list := UserList{OffsetLimit: pg.OffsetLimit{Limit: ptrUint64(10)}}

		require.NoError(list.Scan(mockRow{values: []any{
			userID,
			"Test User",
			"user@example.com",
			map[string]any{"team": "auth"},
			&status,
			createdAt,
			(*time.Time)(nil),
			(*time.Time)(nil),
			map[string]any{"role": "admin"},
			[]string{"staff"},
			[]string{"openid"},
		}}))
		assert.Len(list.Body, 1)

		require.NoError(list.ScanCount(mockRow{values: []any{uint(2)}}))
		assert.Equal(uint(2), list.Count)
		require.NotNil(list.Limit)
		assert.Equal(uint64(2), *list.Limit)
	})

	t.Run("UserMetaInsertAndUpdate", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		expiresAt := time.Now().UTC().Add(time.Hour)
		status := UserStatusActive
		meta := UserMeta{
			Name:      "Test User",
			Email:     "USER@EXAMPLE.COM",
			Status:    &status,
			Meta:      map[string]any{"a": 1},
			ExpiresAt: &expiresAt,
		}
		bind := pg.NewBind("schema", DefaultSchema)
		query, err := meta.Insert(bind)
		require.NoError(err)
		assert.NotEmpty(query)
		assert.Equal("user@example.com", bind.Get("email"))

		patchBind := pg.NewBind()
		require.NoError(meta.Update(patchBind))
		assert.True(patchBind.Has("patch"))
	})

	t.Run("UserMetaInsertValidation", func(t *testing.T) {
		assert := assert.New(t)

		_, err := (UserMeta{Name: "Test User"}).Insert(pg.NewBind())
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrBadParameter)

		_, err = (UserMeta{Email: "user@example.com"}).Insert(pg.NewBind())
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrBadParameter)

		badStatus := UserStatus("weird")
		_, err = (UserMeta{Name: "Test User", Email: "user@example.com", Status: &badStatus}).Insert(pg.NewBind())
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrBadParameter)
	})

	t.Run("UserMetaUpdateNoFields", func(t *testing.T) {
		assert := assert.New(t)
		err := (UserMeta{}).Update(pg.NewBind())
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrBadParameter)
	})

	t.Run("UserMetaUpdateValidation", func(t *testing.T) {
		assert := assert.New(t)

		badStatus := UserStatus("weird")
		err := (UserMeta{Status: &badStatus}).Update(pg.NewBind())
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrBadParameter)

		err = (UserMeta{Email: "not-an-email"}).Update(pg.NewBind())
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrBadParameter)

		zero := time.Time{}
		bind := pg.NewBind()
		err = (UserMeta{ExpiresAt: &zero}).Update(bind)
		assert.NoError(err)
		patch, ok := bind.Get("patch").(string)
		require.True(t, ok)
		assert.Contains(patch, "expires_at = NULL")

		bind = pg.NewBind()
		err = (UserMeta{Meta: map[string]any{"team": "platform", "admin": true, "region": nil}}).Update(bind)
		assert.NoError(err)
		patch, ok = bind.Get("patch").(string)
		require.True(t, ok)
		assert.Equal("admin", bind.Get("meta_key_0"))
		assert.Equal("true", bind.Get("meta_value_0"))
		assert.Equal("region", bind.Get("meta_key_1"))
		assert.Equal("team", bind.Get("meta_key_2"))
		assert.Equal(`"platform"`, bind.Get("meta_value_2"))
		assert.Contains(patch, "meta = ")
		assert.Contains(patch, "jsonb_build_object(")
		assert.Contains(patch, " - @meta_key_1")
		assert.True(strings.Contains(patch, `COALESCE("meta", '{}'::jsonb)`))
	})

	t.Run("UserListRequestSelect", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		req := UserListRequest{Email: "user@example.com", Status: []UserStatus{UserStatusActive}}
		bind := pg.NewBind("schema", DefaultSchema)
		query, err := req.Select(bind, pg.List)
		require.NoError(err)
		assert.NotEmpty(query)
		assert.True(bind.Has("orderby"))
		assert.Equal(`ORDER BY user_row.email ASC, user_row.id ASC`, bind.Get("orderby"))

		_, err = (UserListRequest{Email: "not-an-email"}).Select(pg.NewBind(), pg.List)
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrBadParameter)

		_, err = (UserListRequest{Status: []UserStatus{UserStatus("weird")}}).Select(pg.NewBind(), pg.List)
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrBadParameter)

		_, err = req.Select(pg.NewBind(), pg.Get)
		assert.Error(err)
		assert.ErrorIs(err, auth.ErrNotImplemented)
	})
}
