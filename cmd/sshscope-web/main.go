// Command sshscope-web serves the sshscope UI and API on an HTTP port.
package main

import (
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sshscope/sshscope/internal/web"
)

var version = "dev"

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	address := flag.String("listen", "127.0.0.1:8080", "HTTP listen address")
	flag.Parse()
	if _, _, err := net.SplitHostPort(*address); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "invalid listen address: %v\n", err)
		os.Exit(2)
	}
	handler, err := web.NewHandler(web.NewService(version), assets)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "initialize web handler: %v\n", err)
		os.Exit(2)
	}
	server := web.Server(*address, handler)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	fmt.Printf("sshscope web UI listening on http://%s\n", *address)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		_, _ = fmt.Fprintf(os.Stderr, "serve web UI: %v\n", err)
		os.Exit(1)
	}
}
