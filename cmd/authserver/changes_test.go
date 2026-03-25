package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	// Packages
	httphandler "github.com/djthorpe/go-auth/pkg/httphandler"
	httprouter "github.com/mutablelogic/go-server/pkg/httprouter"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestChangesRouteRegisteredUnderAPIPrefix(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	router, err := httprouter.NewRouter(context.Background(), "/api", "", "Test API", "1.0.0")
	require.NoError(err)
	require.NoError(httphandler.RegisterHandlers(nil, router, false))

	req := httptest.NewRequest(http.MethodGet, "/api/changes", nil)
	req.Header.Set("Accept", "application/json")
	res := httptest.NewRecorder()

	router.ServeHTTP(res, req)

	assert.Equal(http.StatusNotAcceptable, res.Code)
	assert.Contains(res.Body.String(), "text/event-stream")
}
