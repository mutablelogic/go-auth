package view

import (
	// Packages
	carbon "github.com/djthorpe/go-wasmbuild/pkg/carbon"
	mvc "github.com/djthorpe/go-wasmbuild/pkg/mvc"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// GroupsView is the placeholder page container for groups.
type GroupsView struct {
	mvc.View
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func NewGroupsView() *GroupsView {
	page := carbon.Page()
	return &GroupsView{View: page}
}
