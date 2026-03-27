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
	"encoding/json"
	"strings"

	// Packages
	auth "github.com/djthorpe/go-auth/wasm/frontend/pkg/auth"
	view "github.com/djthorpe/go-auth/wasm/frontend/pkg/view"
	dom "github.com/djthorpe/go-wasmbuild"
	js "github.com/djthorpe/go-wasmbuild/pkg/js"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// SessionController coordinates authenticated session state in the user menu.
type SessionController struct {
	auth *auth.Auth
	view *view.UserMenuView
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// NewSessionController creates a controller for session refresh and logout actions.
func NewSessionController(auth *auth.Auth) *SessionController {
	return &SessionController{auth: auth}
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// Bind wires the controller to the user menu view and loads the current session.
func (controller *SessionController) Bind(view *view.UserMenuView) *SessionController {
	if controller == nil || controller.auth == nil || view == nil {
		return controller
	}
	controller.view = view
	view.OnRefresh(func(dom.Event) {
		controller.refresh()
	})
	view.OnLogout(func(dom.Event) {
		controller.logout()
	})
	controller.refresh()
	return controller
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func (controller *SessionController) refresh() {
	if controller == nil || controller.auth == nil || controller.view == nil {
		return
	}
	controller.view.SetLoading()
	controller.auth.UserInfo(func(userinfo string) {
		primary, secondary := summarizeUserInfo(userinfo)
		controller.view.SetSession(primary, secondary)
	}, func(err error) {
		controller.view.SetError(errorString(err))
	})
}

func (controller *SessionController) logout() {
	if controller == nil || controller.auth == nil {
		return
	}
	controller.auth.Logout(func() {
		js.Global().Get("location").Set("href", "/")
	}, func(err error) {
		js.Global().Get("console").Call("error", errorString(err))
	})
}

func summarizeUserInfo(userinfo string) (string, string) {
	var payload map[string]any
	if err := json.Unmarshal([]byte(userinfo), &payload); err != nil {
		compact := strings.TrimSpace(userinfo)
		if compact == "" {
			return "User details unavailable", "No session fields returned."
		}
		return "Signed in", compact
	}
	primary := firstNonEmpty(payload, "name", "preferred_username", "email", "sub")
	secondary := firstNonEmpty(payload, "email", "preferred_username", "sub")
	if primary == "" {
		primary = "Signed in"
	}
	if secondary == "" || secondary == primary {
		secondary = "Session is active."
	}
	return primary, secondary
}

func firstNonEmpty(payload map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := payload[key]; ok {
			if text := strings.TrimSpace(strings.Trim(fmtAny(value), `"`)); text != "" {
				return text
			}
		}
	}
	return ""
}

func fmtAny(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(encoded)
}
