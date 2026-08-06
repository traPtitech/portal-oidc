package main

import (
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/alecthomas/kong"
)

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
	log.Printf("Starting server on %s", srv.Addr)
	return srv.ListenAndServe()
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

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
