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
	a.setMethod(object, "getUserInfo", a.handleGetUserInfo)
	a.setMethod(object, "refreshToken", a.handleRefreshToken)
	a.setMethod(object, "revokeToken", a.handleRevokeToken)
	js.Global().Set("GoAuthBridge", object)
}

func (a *Auth) UserInfo(onSuccess func(string), onError func(error)) {
	a.fetchUserInfo(onSuccess, onError)
}

func (a *Auth) Refresh(onSuccess func(string), onError func(error)) {
	token, err := storedToken()
	if err != nil {
		callError(onError, err)
		return
	}

	api, err := requireGlobal("AuthAPI")
	if err != nil {
		callError(onError, err)
		return
	}

	store, err := requireGlobal("AuthToken")
	if err != nil {
		callError(onError, err)
		return
	}

	js.FromJSPromise(api.Call("refreshToken", token)).Done(func(value js.Value, err error) {
		if err != nil {
			callError(onError, err)
			return
		}

		refreshed := strings.TrimSpace(value.Get("token").String())
		if refreshed == "" {
			callError(onError, fmt.Errorf("refresh response missing token"))
			return
		}

		store.Call("storeToken", refreshed)
		a.fetchUserInfo(onSuccess, onError)
	})
}

func (a *Auth) Logout(onSuccess func(), onError func(error)) {
	token, err := storedToken()
	if err != nil {
		callError(onError, err)
		return
	}

	api, err := requireGlobal("AuthAPI")
	if err != nil {
		callError(onError, err)
		return
	}

	store, err := requireGlobal("AuthToken")
	if err != nil {
		callError(onError, err)
		return
	}

	js.FromJSPromise(api.Call("revokeToken", token)).Done(func(value js.Value, err error) {
		if err != nil {
			callError(onError, err)
			return
		}

		store.Call("clearStoredToken")
		if onSuccess != nil {
			onSuccess()
		}
	})
}

func (a *Auth) setMethod(object js.Value, name string, fn func(js.Value, []js.Value) any) {
	wrapped := js.NewFunc(fn)
	a.funcs = append(a.funcs, wrapped)
	object.Set(name, wrapped)
}

func (a *Auth) handleGetUserInfo(this js.Value, args []js.Value) any {
	return newPromise(func(resolve, reject js.Value) {
		defer recoverToReject(reject)

		a.fetchUserInfoValue(func(value js.Value, err error) {
			if err != nil {
				rejectWithError(reject, err)
				return
			}

			resolve.Invoke(value)
		})
	})
}

func (a *Auth) handleRefreshToken(this js.Value, args []js.Value) any {
	return newPromise(func(resolve, reject js.Value) {
		defer recoverToReject(reject)

		a.refreshTokenValue(func(value js.Value, err error) {
			if err != nil {
				rejectWithError(reject, err)
				return
			}

			resolve.Invoke(value)
		})
	})
}

func (a *Auth) handleRevokeToken(this js.Value, args []js.Value) any {
	return newPromise(func(resolve, reject js.Value) {
		defer recoverToReject(reject)

		a.revokeTokenValue(func(value js.Value, err error) {
			if err != nil {
				rejectWithError(reject, err)
				return
			}

			resolve.Invoke(value)
		})
	})
}

func (a *Auth) fetchUserInfo(onSuccess func(string), onError func(error)) {
	a.fetchUserInfoValue(func(value js.Value, err error) {
		if err != nil {
			callError(onError, err)
			return
		}

		userinfo, err := jsonStringFromValue(value)
		if err != nil {
			callError(onError, err)
			return
		}

		if onSuccess != nil {
			onSuccess(userinfo)
		}
	})
}

func (a *Auth) fetchUserInfoValue(done func(js.Value, error)) {
	token, err := storedToken()
	if err != nil {
		done(js.Undefined(), err)
		return
	}

	api, err := requireGlobal("AuthAPI")
	if err != nil {
		done(js.Undefined(), err)
		return
	}

	js.FromJSPromise(api.Call("fetchUserInfo", token)).Done(done)
}

func (a *Auth) refreshTokenValue(done func(js.Value, error)) {
	token, err := storedToken()
	if err != nil {
		done(js.Undefined(), err)
		return
	}

	api, err := requireGlobal("AuthAPI")
	if err != nil {
		done(js.Undefined(), err)
		return
	}

	store, err := requireGlobal("AuthToken")
	if err != nil {
		done(js.Undefined(), err)
		return
	}

	js.FromJSPromise(api.Call("refreshToken", token)).Done(func(value js.Value, err error) {
		if err != nil {
			done(js.Undefined(), err)
			return
		}

		refreshed := strings.TrimSpace(value.Get("token").String())
		if refreshed == "" {
			done(js.Undefined(), fmt.Errorf("refresh response missing token"))
			return
		}

		store.Call("storeToken", refreshed)
		a.fetchUserInfoValue(done)
	})
}

func (a *Auth) revokeTokenValue(done func(js.Value, error)) {
	token, err := storedToken()
	if err != nil {
		done(js.Undefined(), err)
		return
	}

	api, err := requireGlobal("AuthAPI")
	if err != nil {
		done(js.Undefined(), err)
		return
	}

	store, err := requireGlobal("AuthToken")
	if err != nil {
		done(js.Undefined(), err)
		return
	}

	js.FromJSPromise(api.Call("revokeToken", token)).Done(func(value js.Value, err error) {
		if err != nil {
			done(js.Undefined(), err)
			return
		}

		store.Call("clearStoredToken")
		done(value, nil)
	})
}

func jsonStringFromValue(value js.Value) (string, error) {
	encoded := js.Global().Get("JSON").Call("stringify", value).String()
	if encoded == "" {
		return "", fmt.Errorf("userinfo payload is empty")
	}
	return encoded, nil
}

func callError(fn func(error), err error) {
	if fn != nil {
		fn(err)
	}
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
