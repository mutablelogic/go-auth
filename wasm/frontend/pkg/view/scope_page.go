package view

import (
	// Packages
	carbon "github.com/djthorpe/go-wasmbuild/pkg/carbon"
	mvc "github.com/djthorpe/go-wasmbuild/pkg/mvc"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// ScopesView is the placeholder page container for scopes.
type ScopesView struct {
	mvc.View
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func NewScopesView() *ScopesView {
	page := carbon.Page()
	return &ScopesView{View: page}
}
