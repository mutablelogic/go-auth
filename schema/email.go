package schema

import (
	"strings"

	// Packages
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func canonicalizeEmail(email string) string {
	email = strings.TrimSpace(email)
	if email == "" {
		return ""
	}
	var normalized string
	if types.IsEmail(email, nil, &normalized) {
		return strings.ToLower(strings.TrimSpace(normalized))
	}
	return strings.ToLower(email)
}
