package web

import (
	"embed"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

//go:embed testdata/dist/*
var testAssets embed.FS

func TestHandlerDefaults(t *testing.T) {
	handler, err := NewHandler(NewService("test"), testAssets)
	if err != nil {
		t.Fatalf("NewHandler() = %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/defaults", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"port":22`) {
		t.Fatalf("defaults body = %s", response.Body.String())
	}
}

func TestHandlerRejectsUnknownScanField(t *testing.T) {
	handler, err := NewHandler(NewService("test"), testAssets)
	if err != nil {
		t.Fatalf("NewHandler() = %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(`{"targets":"127.0.0.1","surprise":true}`))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
}
