package main

import (
	"testing"

	// Packages
	kong "github.com/alecthomas/kong"
	schema "github.com/djthorpe/go-auth/schema"
	require "github.com/stretchr/testify/require"
)

func TestUserJoinCommandParse(t *testing.T) {
	var cli CLI
	parser, err := kong.New(&cli, kong.Name("authserver"))
	require.NoError(t, err)

	_, err = parser.Parse([]string{"user-join", "11111111-1111-1111-1111-111111111111", "admins", "editors"})
	require.NoError(t, err)

	require.Equal(t, mustUserID(t, "11111111-1111-1111-1111-111111111111"), cli.UserGroupCommands.UserJoin.UserID)
	require.Equal(t, schema.UserGroupList{"admins", "editors"}, cli.UserGroupCommands.UserJoin.Groups)
}

func TestUserLeaveCommandParse(t *testing.T) {
	var cli CLI
	parser, err := kong.New(&cli, kong.Name("authserver"))
	require.NoError(t, err)

	_, err = parser.Parse([]string{"user-leave", "11111111-1111-1111-1111-111111111111", "admins", "editors"})
	require.NoError(t, err)

	require.Equal(t, mustUserID(t, "11111111-1111-1111-1111-111111111111"), cli.UserGroupCommands.UserLeave.UserID)
	require.Equal(t, schema.UserGroupList{"admins", "editors"}, cli.UserGroupCommands.UserLeave.Groups)
}

func mustUserID(t *testing.T, value string) schema.UserID {
	t.Helper()

	userID, err := schema.UserIDFromString(value)
	require.NoError(t, err)

	return userID
}
