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
	dom "github.com/djthorpe/go-wasmbuild"
	carbon "github.com/djthorpe/go-wasmbuild/pkg/carbon"
	mvc "github.com/djthorpe/go-wasmbuild/pkg/mvc"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// UserMenuView renders the authenticated user overflow menu.
type UserMenuView struct {
	mvc.View
	summary mvc.View
	detail  mvc.View
	refresh mvc.View
	logout  mvc.View
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func NewUserMenuView(itemSize, iconSize carbon.Attr) *UserMenuView {
	summary := carbon.OverflowMenuItem("Loading session...").SetEnabled(false)
	summary.Apply(carbon.With(itemSize)...)

	detail := carbon.OverflowMenuItem("Fetching current user info.").SetEnabled(false)
	detail.Apply(carbon.With(itemSize)...)

	refresh := carbon.OverflowMenuItem("Refresh session").SetDivider(true)
	refresh.Apply(carbon.With(itemSize)...)

	logout := carbon.OverflowMenuItem("Logout").SetDanger(true)
	logout.Apply(carbon.With(itemSize)...)

	menu := carbon.OverflowMenu(
		mvc.WithID("user-info"),
		carbon.Icon(carbon.IconUserAvatar, carbon.With(iconSize)),
	).SetLabel("User information")
	menu.Content(summary, detail, refresh, logout)

	return &UserMenuView{
		View:    menu,
		summary: summary,
		detail:  detail,
		refresh: refresh,
		logout:  logout,
	}
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (view *UserMenuView) SetLoading() {
	if view == nil {
		return
	}
	view.setLabel(view.summary, "Loading session...")
	view.setLabel(view.detail, "Fetching current user info.")
}

func (view *UserMenuView) SetSession(primary, secondary string) {
	if view == nil {
		return
	}
	view.setLabel(view.summary, primary)
	view.setLabel(view.detail, secondary)
}

func (view *UserMenuView) SetError(text string) {
	if view == nil {
		return
	}
	view.setLabel(view.summary, "Session unavailable")
	view.setLabel(view.detail, text)
}

func (view *UserMenuView) OnRefresh(handler func(dom.Event)) {
	if view == nil || view.refresh == nil || handler == nil {
		return
	}
	view.refresh.AddEventListener(carbon.EventOverflowMenuItemClick, handler)
}

func (view *UserMenuView) OnLogout(handler func(dom.Event)) {
	if view == nil || view.logout == nil || handler == nil {
		return
	}
	view.logout.AddEventListener(carbon.EventOverflowMenuItemClick, handler)
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func (view *UserMenuView) setLabel(item mvc.View, label string) {
	if item == nil {
		return
	}
	item.Root().SetInnerHTML(label)
}
