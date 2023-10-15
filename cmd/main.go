package main

import (
	"log"

	"github.com/spf13/cobra"
	"github.com/traPtitech/portal-oidc/pkg/util"
)

var (
	configFilePath string
	config         Config
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
			return nil
		},
	})

	flags := rootCommand.PersistentFlags()
	flags.StringVarP(&configFilePath, "config", "c", "", "config file path (default: ./config.*)")

	if err := rootCommand.Execute(); err != nil {
		log.Fatal(err)
	}
}
