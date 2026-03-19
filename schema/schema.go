package schema

import (
	_ "embed"
	"time"
)

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

//go:embed objects.sql
var Objects string

//go:embed queries.sql
var Queries string

const (
	DefaultSchema     = "auth"
	DefaultSessionTTL = time.Minute * 15
)

const (
	IdentityListMax = 100
	UserListMax     = 100
)
