package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/alecthomas/kong"
)

type CLI struct {
	Config string   `short:"c" help:"Config file path (default: ./config.yaml)" type:"path"`
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
	return srv.ListenAndServe()
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
