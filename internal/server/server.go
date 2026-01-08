package server

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/rs/cors"
)

func NewServer(config Config) http.Handler {
	e := echo.New()

	return cors.New(cors.Options{
		AllowOriginFunc: func(origin string) bool {
			return true
		},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
	}).Handler(e)
}
