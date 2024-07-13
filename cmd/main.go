package main

import (
	"log"
	"net/http"

	"github.com/spf13/cobra"

	"github.com/traPtitech/portal-oidc/pkg/server"
	"github.com/traPtitech/portal-oidc/pkg/util"
)

var (
	configFilePath string
	config         server.Config
)

var rootCommand = &cobra.Command{
	Use:   "portal-oidc",
	Short: "Potal OIDC Server",
}

func main() {
	cobra.OnInitialize(util.CobraOnInitializeFunc(&configFilePath, "OIDC", &config))

	rootCommand.AddCommand(&cobra.Command{
		Use:   "serve",
		Short: "Starts the server",
		RunE: func(cmd *cobra.Command, args []string) error {
			srv := server.NewServer(config)
			return http.ListenAndServe(":8080", srv)
		},
	})

	flags := rootCommand.PersistentFlags()
	flags.StringVarP(&configFilePath, "config", "c", "", "config file path (default: ./config.*)")
	setupDefaults()

	if err := rootCommand.Execute(); err != nil {
		log.Fatal(err)
	}
}
