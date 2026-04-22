package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"syscall/js"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type TokenValue struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
	Expiry       string `json:"expiry,omitempty"`
	StoredAt     string `json:"stored_at,omitempty"`
}

type Token struct {
	value js.Value
}

var (
	ErrTokenUnavailable = errors.New("window.Token is not available")
	ErrTokenMissing     = errors.New("token value is not available")
	ErrTokenInvalid     = errors.New("token value is invalid")
)

const (
	DefaultSkewMS = 10 * 1000 // 10 seconds skew for token expiry validation
)

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// NewToken binds to window.Token and returns a JavaScript Token instance.
func NewToken(key string) (*Token, error) {
	class := js.Global().Get("Token")
	if class.IsUndefined() || class.IsNull() {
		return nil, ErrTokenUnavailable
	}
	if class.Type() != js.TypeFunction {
		return nil, fmt.Errorf("window.Token has type %s, want function", class.Type())
	}
	instance := class.New(tokenArgs(key, DefaultSkewMS)...)
	return &Token{value: instance}, nil
}

func (t *Token) JSValue() js.Value {
	if t == nil {
		return js.Null()
	}
	return t.value
}

func (t *Token) Read() (*TokenValue, error) {
	if err := t.ensure(); err != nil {
		return nil, err
	}
	return tokenValueFromJS(t.value.Call("read"))
}

func (t *Token) Write(value *TokenValue) (*TokenValue, error) {
	if err := t.ensure(); err != nil {
		return nil, err
	}
	if value == nil {
		return nil, ErrTokenMissing
	}
	encoded, err := jsValueFromTokenValue(value)
	if err != nil {
		return nil, err
	}
	return tokenValueFromJS(t.value.Call("write", encoded))
}

func (t *Token) Delete() (*TokenValue, error) {
	if err := t.ensure(); err != nil {
		return nil, err
	}
	value, err := t.Read()
	if err != nil {
		return nil, err
	}
	t.value.Call("delete")
	return value, nil
}

func (t *Token) Valid(value ...*TokenValue) (*TokenValue, error) {
	if err := t.ensure(); err != nil {
		return nil, err
	}

	if len(value) > 0 {
		token := value[0]
		if token == nil {
			return nil, ErrTokenMissing
		}
		encoded, err := jsValueFromTokenValue(token)
		if err != nil {
			return nil, err
		}
		if !t.value.Call("valid", encoded).Bool() {
			return nil, ErrTokenInvalid
		}
		return token, nil
	}

	token, err := t.Read()
	if err != nil {
		return nil, err
	}
	if !t.value.Call("valid").Bool() {
		return nil, ErrTokenInvalid
	}
	return token, nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func (t *Token) ensure() error {
	if t == nil || t.value.IsUndefined() || t.value.IsNull() {
		return ErrTokenUnavailable
	}
	return nil
}

func tokenArgs(key string, skew int) []any {
	args := js.Global().Get("Object").New()
	args.Set("key", key)
	args.Set("expirySkewMs", skew)
	return []any{args}
}

func tokenValueFromJS(value js.Value) (*TokenValue, error) {
	if value.IsUndefined() || value.IsNull() {
		return nil, ErrTokenMissing
	}
	encoded := js.Global().Get("JSON").Call("stringify", value).String()
	if encoded == "" || encoded == "undefined" || encoded == "null" {
		return nil, ErrTokenMissing
	}
	var token TokenValue
	if err := json.Unmarshal([]byte(encoded), &token); err != nil {
		return nil, fmt.Errorf("decode token value: %w", err)
	}
	if token.AccessToken == "" {
		return nil, ErrTokenInvalid
	}
	return &token, nil
}

func jsValueFromTokenValue(value *TokenValue) (js.Value, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return js.Undefined(), fmt.Errorf("encode token value: %w", err)
	}
	return js.Global().Get("JSON").Call("parse", string(encoded)), nil
}
