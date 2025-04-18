package main

import (
	"api/auth"
	"api/config"
	"api/database"
	"api/handlers"
	"api/repositories"
	"api/services"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"log"
)

// API struct contains the application.
type API struct {
	// Conf stores the configuration of the app.
	Conf     *config.Config
	Handlers handlers.Handlers
}

// start mounts the handlers and binds the app to the specified port.
func (a *API) start() error {
	app := fiber.New()

	// If the api is for debug, add logger for easier development.
	if a.Conf.ApiConfig.IsDebug {
		app.Use(logger.New())
	}

	api := app.Group("/api/v1")

	// Router related to users
	userGroup := api.Group("/users")
	userGroup.Post("/register/client", a.Handlers.UserHandler.RegisterClient())

	return app.Listen(a.Conf.ApiConfig.ServerAddr)
}

// New create a new instance of API.
func New() *API {
	conf := config.NewConfig()
	db, err := database.Connect(conf.DbConfig)
	if err != nil {
		log.Fatalf("Error connecting to database: %v", err)
	}

	return &API{
		Conf: conf,
		Handlers: handlers.Handlers{
			UserHandler: handlers.NewDefaultUserHandler(
				services.NewDefaultUserService(
					repositories.NewPostgresUserRepository(db),
					auth.NewJWTAuthenticator(*conf.AuthConfig),
				),
			),
		},
	}
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Printf("Error loading .env file")
	}
	api := New()
	err = api.start()
	log.Fatalf("Error starting the API with error: %v and configration: %+v", err, api.Conf)
}
