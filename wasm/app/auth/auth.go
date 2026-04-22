package auth

import (
	"encoding/json"
	"fmt"
	"net/url"

	// Packages
	js "github.com/djthorpe/go-wasmbuild/pkg/js"
	mvc "github.com/mutablelogic/go-auth/wasm/app/mvc"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type Auth struct {
	token *Token
	url   *url.URL
	mvc.Observable
}

type RevokeRequest struct {
	Token string `json:"token"`
}

const (
	EventRevoke = "auth-revoke"
	EventError  = "auth-error"
)

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// New binds to window.Auth and returns a JavaScript Auth instance.
func New(baseUrl string, key string) (*Auth, error) {
	self := new(Auth)

	// Set the URL
	if parsedUrl, err := url.Parse(baseUrl); err != nil {
		return nil, err
	} else {
		self.url = parsedUrl
	}

	// Set the token
	if token, err := NewToken(key); err != nil {
		return nil, err
	} else {
		self.token = token
	}

	// Return success
	return self, nil
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// Valid returns true if the stored token is valid, false otherwise.
func (a *Auth) Valid() bool {
	if value, err := a.token.Valid(); err != nil || value == nil {
		return false
	}
	return true
}

// Revoke revokes the current token and notifies listeners of the "revoke" event.
func (a *Auth) Revoke() error {
	token, err := a.token.Read()
	if err != nil {
		return err
	}
	js.Fetch(a.url.JoinPath("auth/revoke").String(),
		js.WithMethod("POST"),
		js.WithJSON(stringify(RevokeRequest{Token: token.AccessToken})),
	).Done(func(value js.Value, err error) {
		if err != nil {
			a.Notify(&mvc.Event{
				Name:   EventError,
				Target: a,
				Data:   err,
			})
			return
		}
		response := js.ResponseFrom(value)
		if response == nil {
			a.Notify(&mvc.Event{
				Name:   EventError,
				Target: a,
				Data:   fmt.Errorf("revoke failed: missing response"),
			})
			return
		}
		if response.OK() {
			if _, deleteErr := a.token.Delete(); deleteErr != nil {
				a.Notify(&mvc.Event{
					Name:   EventError,
					Target: a,
					Data:   deleteErr,
				})
			}
			a.Notify(&mvc.Event{
				Name:   EventRevoke,
				Target: a,
				Data:   token,
			})
			return
		}

		response.Text().Done(func(body js.Value, bodyErr error) {
			if bodyErr != nil {
				a.Notify(&mvc.Event{
					Name:   EventError,
					Target: a,
					Data:   bodyErr,
				})
			} else {
				a.Notify(&mvc.Event{
					Name:   EventError,
					Target: a,
					Data:   body.String(),
				})
			}
		})
	})

	return nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func stringify(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		return err.Error()
	}
	return string(data)
}
