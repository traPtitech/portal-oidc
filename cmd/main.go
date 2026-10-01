package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/labstack/echo/v5"
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var shutdownErr error
	sc := echo.StartConfig{
		Address:         ":8080",
		HideBanner:      true,
		GracefulTimeout: shutdownTimeout,
		BeforeServeFunc: func(srv *http.Server) error {
			// Preserve the existing timeouts instead of Echo's default ReadTimeout.
			srv.ReadTimeout = 0
			srv.ReadHeaderTimeout = 10 * time.Second
			return nil
		},
		OnShutdownError: func(err error) {
			shutdownErr = err
		},
	}
	if err := sc.Start(ctx, handler); err != nil {
		return err
	}
	// Start waits for shutdown, including OnShutdownError, before returning.
	return shutdownErr
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
