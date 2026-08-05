package web

import (
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"strings"
	"time"
)

type Handler struct {
	service *Service
	assets  http.Handler
}

func NewHandler(service *Service, embedded embed.FS) (*Handler, error) {
	assets, err := fs.Sub(embedded, "frontend/dist")
	if err != nil {
		return nil, err
	}
	return &Handler{service: service, assets: http.FileServer(http.FS(assets))}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/defaults":
		writeJSON(w, http.StatusOK, h.service.Defaults())
	case r.Method == http.MethodPost && r.URL.Path == "/api/scan":
		h.handleScan(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/api/cancel":
		writeJSON(w, http.StatusOK, map[string]bool{"cancelled": h.service.Cancel()})
	case strings.HasPrefix(r.URL.Path, "/api/"):
		writeError(w, http.StatusNotFound, "API endpoint not found")
	default:
		h.assets.ServeHTTP(w, r)
	}
}

func (h *Handler) handleScan(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, MaximumScanRequestBytes)
	defer r.Body.Close()
	var input ScanInput
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err == nil {
		writeError(w, http.StatusBadRequest, "request must contain exactly one JSON value")
		return
	}
	output, err := h.service.Scan(r.Context(), input)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, http.ErrAbortHandler) {
			status = http.StatusInternalServerError
		} else if strings.Contains(err.Error(), "already running") {
			status = http.StatusConflict
		}
		writeError(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, output)
}

func Server(address string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      10 * time.Minute,
		IdleTimeout:       30 * time.Second,
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
