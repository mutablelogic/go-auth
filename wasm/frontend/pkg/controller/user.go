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

package controller

import (
	"fmt"
	"net/url"

	// Packages
	schema "github.com/mutablelogic/go-auth/auth/schema"
	provider "github.com/mutablelogic/go-auth/wasm/frontend/pkg/provider"
	dom "github.com/djthorpe/go-wasmbuild"
	carbon "github.com/djthorpe/go-wasmbuild/pkg/carbon"
	js "github.com/djthorpe/go-wasmbuild/pkg/js"
	mvc "github.com/djthorpe/go-wasmbuild/pkg/mvc"
	pg "github.com/mutablelogic/go-pg"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// UserController coordinates user resource operations for the frontend.
type UserController struct {
	*provider.UserProvider
	Users schema.UserList
	Err   error
	list  userListView
	panel userPanelView
}

type userListView interface {
	mvc.View
	mvc.PaginationState
	mvc.VisibleState
	CreateUserButton() mvc.View
	SetLoading()
}

type userPanelView interface {
	mvc.View
	mvc.VisibleState
	CloseButton() mvc.View
	CreateButton() mvc.View
	UserMeta() schema.UserMeta
	Reset()
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// NewUserController creates a user controller with an attached user provider.
func NewUserController(base *url.URL) *UserController {
	return &UserController{
		UserProvider: provider.NewUserProvider(base),
	}
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// Bind registers the controller to fetch users whenever the bound list view is activated by the router,
// and coordinates open/close behavior with the user panel view.
func (controller *UserController) Bind(list userListView, panel userPanelView) *UserController {
	if controller == nil || list == nil || panel == nil {
		return controller
	}
	controller.list = list
	controller.panel = panel
	list.AddEventListener(mvc.EventRouterActivate, func(dom.Event) {
		list.SetLoading()
		controller.refresh()
	})
	list.AddEventListener(carbon.EventPaginationChanged, func(dom.Event) {
		list.SetLoading()
		controller.refresh()
	})
	list.AddEventListener(carbon.EventPaginationPageSize, func(dom.Event) {
		list.SetLoading()
		controller.refresh()
	})
	if button := list.CreateUserButton(); button != nil {
		button.AddEventListener(carbon.EventClick, func(dom.Event) {
			if controller.panel != nil {
				controller.panel.SetVisible(true)
			}
		})
	}
	if button := panel.CloseButton(); button != nil {
		button.AddEventListener(carbon.EventClick, func(dom.Event) {
			if controller.panel != nil {
				controller.panel.SetVisible(false)
			}
		})
	}
	if button := panel.CreateButton(); button != nil {
		button.AddEventListener(carbon.EventClick, func(dom.Event) {
			controller.createUser()
		})
	}
	return controller
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func (controller *UserController) refresh() {
	if controller == nil || controller.UserProvider == nil {
		return
	}

	controller.List(controller.request()).Done(func(users schema.UserList, err error) {
		controller.Users = users
		controller.Err = err
		if err != nil {
			js.Global().Get("console").Call("error", errorString(err))
			return
		}
		if controller.list != nil {
			controller.list.Content(users)
		}
	})
}

func (controller *UserController) request() schema.UserListRequest {
	req := schema.UserListRequest{}
	if controller == nil || controller.list == nil {
		return req
	}
	req.Offset = uint64(controller.list.Offset())
	if limit := controller.list.Limit(); limit > 0 {
		value := uint64(limit)
		req.OffsetLimit = pg.OffsetLimit{
			Offset: req.Offset,
			Limit:  &value,
		}
	}
	return req
}

func (controller *UserController) createUser() {
	if controller == nil || controller.UserProvider == nil || controller.panel == nil {
		return
	}
	meta := controller.panel.UserMeta()
	controller.Post(meta).Done(func(_ schema.User, err error) {
		controller.Err = err
		if err != nil {
			js.Global().Get("console").Call("error", errorString(err))
			return
		}
		controller.panel.Reset()
		controller.panel.SetVisible(false)
		if controller.list != nil {
			controller.list.SetLoading()
		}
		controller.refresh()
	})
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprint(err)
}
