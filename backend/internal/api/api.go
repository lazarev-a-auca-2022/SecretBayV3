package api

import (
	"net/http"
	"path/filepath"
	"time"

	"github.com/gorilla/mux"
	"github.com/secretbay/backend/internal/config"
	"github.com/sirupsen/logrus"
)

// RegisterHandlers registers all API handlers on the given router
func RegisterHandlers(router *mux.Router, log *logrus.Logger, cfg *config.Config) {
	// Health check endpoint
	router.HandleFunc("/api/health", HealthCheckHandler()).Methods("GET")

	// VPN configuration endpoints
	router.HandleFunc("/api/vpn/configure", ConfigureVPNHandler(log, cfg)).Methods("POST")

	// File download endpoint - serve files from the public directory
	publicDir := filepath.Join(cfg.TempDir, "public")
	fileServer := http.FileServer(http.Dir(publicDir))
	router.PathPrefix("/download/").Handler(http.StripPrefix("/download/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add cache control headers
		w.Header().Set("Cache-Control", "no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")

		// Serve the file
		fileServer.ServeHTTP(w, r)
	}))).Methods("GET")
}

// HealthCheckHandler returns a simple health check handler
func HealthCheckHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","time":"` + time.Now().Format(time.RFC3339) + `"}`))
	}
}
