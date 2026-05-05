package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
)

const shutdownTimeout = 30 * time.Second

type CLI struct {
	Config string   `short:"c" help:"Config file path" type:"path"`
	Serve  ServeCmd `cmd:"" help:"Start the server"`
}

type ServeCmd struct{}

func (s *ServeCmd) Run(cfg *Config) error {
	handler, err := newServer(*cfg)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              ":8080",
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	serveErr := make(chan error, 1)
	go func() {
		log.Printf("Starting server on %s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serveErr:
		return err
	case sig := <-signals:
		log.Printf("Received %s, shutting down...", sig)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}
	return <-serveErr
}

func main() {
	var cli CLI
	parser := kong.Must(&cli,
		kong.Name("portal-oidc"),
		kong.Description("Portal OIDC Server"),
		kong.UsageOnError(),
	)

	ctx, err := parser.Parse(os.Args[1:])
	if err != nil {
		parser.FatalIfErrorf(err)
	}

	cfg, err := loadConfig(cli.Config)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	ctx.FatalIfErrorf(ctx.Run(cfg))
}
