package main

import (
	"api/config"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"log"
)

// API struct contains the application.
type API struct {
	// Conf stores the configuration of the app.
	Conf *config.Config
}

// start mounts the handlers and binds the app to the specified port.
func (a *API) start() error {
	app := fiber.New()

	// If the api is for debug add logger for easier development.
	if a.Conf.ApiConfig.IsDebug {
		app.Use(logger.New())
	}

	return app.Listen(a.Conf.ApiConfig.ServerAddr)
}

// New create a new instance of API.
func New() *API {
	return &API{Conf: config.NewConfig()}
}

func main() {
	api := New()
	err := api.start()
	log.Fatalf("Error starting the API with error: %v and configration: %+v", err, api.Conf)
}
