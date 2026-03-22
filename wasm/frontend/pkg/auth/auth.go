package auth

import (
	"fmt"
	"strings"

	js "github.com/djthorpe/go-wasmbuild/pkg/js"
)

// Auth registers the browser-facing auth helpers and keeps the callback
// functions alive for the lifetime of the app.
type Auth struct {
	funcs []js.Func
}

// New creates and registers the browser auth helpers.
func New() *Auth {
	auth := &Auth{}
	auth.register()
	return auth
}

func (a *Auth) register() {
	object := js.NewObject()
	a.setMethod(object, "getUserInfo", a.getUserInfo)
	a.setMethod(object, "refreshToken", a.refreshToken)
	a.setMethod(object, "revokeToken", a.revokeToken)
	js.Global().Set("GoAuthBridge", object)
}

func (a *Auth) setMethod(object js.Value, name string, fn func(js.Value, []js.Value) any) {
	wrapped := js.NewFunc(fn)
	a.funcs = append(a.funcs, wrapped)
	object.Set(name, wrapped)
}

func (a *Auth) getUserInfo(this js.Value, args []js.Value) any {
	return newPromise(func(resolve, reject js.Value) {
		defer recoverToReject(reject)

		token, err := storedToken()
		if err != nil {
			rejectWithError(reject, err)
			return
		}

		api, err := requireGlobal("AuthAPI")
		if err != nil {
			rejectWithError(reject, err)
			return
		}

		js.FromJSPromise(api.Call("fetchUserInfo", token)).Done(func(value js.Value, err error) {
			if err != nil {
				rejectWithError(reject, err)
				return
			}

			resolve.Invoke(value)
		})
	})
}

func (a *Auth) refreshToken(this js.Value, args []js.Value) any {
	return newPromise(func(resolve, reject js.Value) {
		defer recoverToReject(reject)

		token, err := storedToken()
		if err != nil {
			rejectWithError(reject, err)
			return
		}

		api, err := requireGlobal("AuthAPI")
		if err != nil {
			rejectWithError(reject, err)
			return
		}

		store, err := requireGlobal("AuthToken")
		if err != nil {
			rejectWithError(reject, err)
			return
		}

		js.FromJSPromise(api.Call("refreshToken", token)).Done(func(value js.Value, err error) {
			if err != nil {
				rejectWithError(reject, err)
				return
			}

			refreshed := strings.TrimSpace(value.Get("token").String())
			if refreshed == "" {
				rejectWithError(reject, fmt.Errorf("refresh response missing token"))
				return
			}

			store.Call("storeToken", refreshed)
			resolve.Invoke(value)
		})
	})
}

func (a *Auth) revokeToken(this js.Value, args []js.Value) any {
	return newPromise(func(resolve, reject js.Value) {
		defer recoverToReject(reject)

		token, err := storedToken()
		if err != nil {
			rejectWithError(reject, err)
			return
		}

		api, err := requireGlobal("AuthAPI")
		if err != nil {
			rejectWithError(reject, err)
			return
		}

		store, err := requireGlobal("AuthToken")
		if err != nil {
			rejectWithError(reject, err)
			return
		}

		js.FromJSPromise(api.Call("revokeToken", token)).Done(func(value js.Value, err error) {
			if err != nil {
				rejectWithError(reject, err)
				return
			}

			store.Call("clearStoredToken")
			resolve.Invoke(value)
		})
	})
}

func storedToken() (string, error) {
	store, err := requireGlobal("AuthToken")
	if err != nil {
		return "", err
	}

	token := strings.TrimSpace(store.Call("getStoredToken").String())
	if token == "" {
		return "", fmt.Errorf("missing stored token")
	}

	return token, nil
}

func requireGlobal(name string) (js.Value, error) {
	value := js.Global().Get(name)
	if isMissing(value) {
		return js.Undefined(), fmt.Errorf("missing %s", name)
	}

	return value, nil
}

func newPromise(fn func(resolve, reject js.Value)) js.Value {
	var executor js.Func
	executor = js.NewFunc(func(this js.Value, args []js.Value) any {
		fn(args[0], args[1])
		return nil
	})

	promise := js.Global().Get("Promise").New(executor)
	executor.Release()
	return promise
}

func rejectWithError(reject js.Value, err error) {
	reject.Invoke(js.Global().Get("Error").New(err.Error()))
}

func recoverToReject(reject js.Value) {
	if recovered := recover(); recovered != nil {
		rejectWithError(reject, fmt.Errorf("%v", recovered))
	}
}

func isMissing(value js.Value) bool {
	return value.IsUndefined() || value.IsNull()
}
