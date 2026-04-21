// Copyright 2026 David Thorpe
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package view

import (
	// Packages
	carbon "github.com/djthorpe/go-wasmbuild/pkg/carbon"
	mvc "github.com/djthorpe/go-wasmbuild/pkg/mvc"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// SideNavView renders the primary app side navigation and exposes route items.
type SideNavView struct {
	mvc.View
	users  mvc.View
	groups mvc.View
	scopes mvc.View
}

var _ mvc.ActiveGroup = (*SideNavView)(nil)

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func NewSideNavView() *SideNavView {
	users := carbon.SideNavLink("#users", "Users")
	groups := carbon.SideNavLink("#groups", "Groups")
	scopes := carbon.SideNavLink("#scopes", "Scopes")
	sideNav := carbon.SideNav(users, groups, scopes)

	return &SideNavView{
		View:   sideNav,
		users:  users,
		groups: groups,
		scopes: scopes,
	}
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (view *SideNavView) Users() mvc.View {
	if view == nil {
		return nil
	}
	return view.users
}

func (view *SideNavView) Groups() mvc.View {
	if view == nil {
		return nil
	}
	return view.groups
}

func (view *SideNavView) Scopes() mvc.View {
	if view == nil {
		return nil
	}
	return view.scopes
}

func (view *SideNavView) Active() []mvc.View {
	if view == nil {
		return nil
	}
	if group, ok := view.View.(mvc.ActiveGroup); ok {
		return group.Active()
	}
	return nil
}

func (view *SideNavView) SetActive(views ...mvc.View) mvc.View {
	if view == nil {
		return nil
	}
	if group, ok := view.View.(mvc.ActiveGroup); ok {
		return group.SetActive(views...)
	}
	return view
}
