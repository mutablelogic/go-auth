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
	"strings"

	// Packages
	schema "github.com/mutablelogic/go-auth/schema/auth"
	dom "github.com/djthorpe/go-wasmbuild"
	carbon "github.com/djthorpe/go-wasmbuild/pkg/carbon"
	mvc "github.com/djthorpe/go-wasmbuild/pkg/mvc"
)

const (
	ViewUserPanel     = "go-auth-user-panel"
	viewUserPanelBody = "go-auth-user-panel-body"
	templateUserPanel = `<div><div data-slot="panel"></div></div>`
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// UserPanelView renders a right-side Carbon header panel with a built-in close button.
type UserPanelView struct {
	mvc.View
	panel  mvc.View
	body   mvc.View
	close  mvc.View
	name   mvc.View
	email  mvc.View
	status mvc.View
	create mvc.View
}

type userPanelBody struct{ mvc.View }

var _ mvc.View = (*UserPanelView)(nil)
var _ mvc.VisibleState = (*UserPanelView)(nil)

func init() {
	mvc.RegisterView(ViewUserPanel, func(element dom.Element) mvc.View {
		return mvc.NewViewWithElement(new(UserPanelView), element, setUserPanelView)
	})
	mvc.RegisterView(viewUserPanelBody, func(element dom.Element) mvc.View {
		return mvc.NewViewWithElement(new(userPanelBody), element, setUserPanelBody)
	})
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func NewUserPanelView(args ...any) *UserPanelView {
	return mvc.NewView(new(UserPanelView), ViewUserPanel, templateUserPanel, setUserPanelView, args...).(*UserPanelView)
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (view *UserPanelView) Content(args ...any) mvc.View {
	if view == nil || view.body == nil {
		return view
	}
	view.body.Content(args...)
	return view
}

func (view *UserPanelView) Visible() bool {
	if view == nil || view.panel == nil {
		return false
	}
	if state, ok := view.panel.(mvc.VisibleState); ok {
		return state.Visible()
	}
	return false
}

func (view *UserPanelView) SetVisible(visible bool) mvc.View {
	if view == nil || view.panel == nil {
		return view
	}
	if state, ok := view.panel.(mvc.VisibleState); ok {
		state.SetVisible(visible)
	}
	return view
}

func (view *UserPanelView) CloseButton() mvc.View {
	if view == nil {
		return nil
	}
	return view.close
}

func (view *UserPanelView) NameInput() mvc.View {
	if view == nil {
		return nil
	}
	return view.name
}

func (view *UserPanelView) EmailInput() mvc.View {
	if view == nil {
		return nil
	}
	return view.email
}

func (view *UserPanelView) StatusInput() mvc.View {
	if view == nil {
		return nil
	}
	return view.status
}

func (view *UserPanelView) CreateButton() mvc.View {
	if view == nil {
		return nil
	}
	return view.create
}

func (view *UserPanelView) UserMeta() schema.UserMeta {
	if view == nil {
		return schema.UserMeta{}
	}
	meta := schema.UserMeta{
		Name:  strings.TrimSpace(view.value(view.name)),
		Email: strings.TrimSpace(view.value(view.email)),
	}
	if status := strings.TrimSpace(view.value(view.status)); status != "" {
		userStatus := schema.UserStatus(status)
		meta.Status = &userStatus
	}
	return meta
}

func (view *UserPanelView) Reset() {
	if view == nil {
		return
	}
	view.setValue(view.name, "")
	view.setValue(view.email, "")
	view.setValue(view.status, string(schema.UserStatusNew))
	if dropdown, ok := view.status.(mvc.View); ok {
		children := dropdown.Children()
		for _, child := range children {
			selected := child.Root().GetAttribute("value") == string(schema.UserStatusNew)
			if selected {
				child.Root().SetAttribute("selected", "")
			} else {
				child.Root().RemoveAttribute("selected")
			}
		}
	}
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func setUserPanelView(self mvc.View, child mvc.View) {
	view := self.(*UserPanelView)
	view.View = child
	view.close = carbon.Button(
		carbon.With(carbon.KindGhost),
		carbon.Icon(carbon.IconClose, carbon.With(carbon.IconSize20)),
		mvc.WithAriaLabel("Close"),
	)
	name := carbon.Input(
		mvc.WithAttr("type", "text"),
		mvc.WithAttr("label", "Name"),
		mvc.WithAttr("placeholder", "Full name"),
		mvc.WithAttr("autocomplete", "name"),
		mvc.WithAttr("name", "name"),
		mvc.WithAttr("size", string(carbon.SizeLarge)),
		mvc.WithAttr("required", ""),
	)
	email := carbon.Input(
		mvc.WithAttr("type", "email"),
		mvc.WithAttr("label", "Email"),
		mvc.WithAttr("placeholder", "name@example.com"),
		mvc.WithAttr("autocomplete", "email"),
		mvc.WithAttr("name", "email"),
		mvc.WithAttr("size", string(carbon.SizeLarge)),
		mvc.WithAttr("required", ""),
	)
	status := carbon.Dropdown(
		"",
		mvc.WithAttr("name", "status"),
		mvc.WithAttr("label", "Status"),
		mvc.WithAttr("size", string(carbon.SizeLarge)),
	)
	status.Content(userStatusOptions()...)
	if items := status.Children(); len(items) > 0 {
		status.SetActive(items[0])
	}
	view.name = name
	view.email = email
	view.status = status
	view.create = carbon.Button(
		carbon.With(carbon.KindPrimary),
		"Create",
	)
	view.body = newUserPanelBody()
	view.body.Content(
		carbon.Form(
			mvc.WithStyle("display:grid;gap:1rem"),
			view.name,
			view.email,
			view.status,
			mvc.HTML(
				"DIV",
				mvc.WithStyle("display:flex;justify-content:flex-end;padding-top:0.5rem"),
				view.create,
			),
		),
	)
	view.panel = carbon.HeaderPanel(
		mvc.WithStyle("display:flex;flex-direction:column;block-size:100%"),
		mvc.HTML(
			"DIV",
			mvc.WithStyle("display:flex;align-items:center;justify-content:flex-end;padding:1rem 1rem 0 1rem"),
			view.close,
		),
		mvc.HTML(
			"DIV",
			mvc.WithStyle("padding:0 1rem"),
			mvc.HTML("H3", mvc.WithStyle("margin:0;font-size:1.25rem;font-weight:600"), "Create User"),
			mvc.HTML("P", mvc.WithStyle("margin:0.5rem 0 0;color:var(--cds-text-secondary,#525252)"), "Create a new user account."),
		),
		view.body,
	)
	view.ReplaceSlot("panel", view.panel)
	view.SetVisible(false)
}

func newUserPanelBody() mvc.View {
	return mvc.NewView(new(userPanelBody), viewUserPanelBody, "DIV", setUserPanelBody, mvc.WithStyle("display:grid;gap:1rem;padding:1rem"))
}

func setUserPanelBody(self mvc.View, child mvc.View) {
	self.(*userPanelBody).View = child
}

func (view *UserPanelView) value(field mvc.View) string {
	if field == nil {
		return ""
	}
	return field.Root().Value()
}

func (view *UserPanelView) setValue(field mvc.View, value string) {
	if field == nil {
		return
	}
	field.Root().SetValue(value)
	field.Root().SetAttribute("value", value)
}

func userStatusOptions() []any {
	options := make([]any, 0, 5)
	for _, status := range []schema.UserStatus{
		schema.UserStatusNew,
		schema.UserStatusActive,
		schema.UserStatusInactive,
		schema.UserStatusSuspended,
		schema.UserStatusDeleted,
	} {
		options = append(options, carbon.DropdownItem(
			mvc.WithAttr("value", string(status)),
			userStatusLabel(status),
		))
	}
	return options
}

func userStatusLabel(status schema.UserStatus) string {
	return strings.ToUpper(string(status[:1])) + string(status[1:])
}
