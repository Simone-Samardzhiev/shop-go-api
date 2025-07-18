package main

import (
	jwtware "github.com/gofiber/contrib/jwt"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"log"
	"net/http"
	"shop/cmd/api/internal/auth"
	"shop/cmd/api/internal/config"
	"shop/cmd/api/internal/database"
	"shop/cmd/api/internal/handlers"
	"shop/cmd/api/internal/repositories"
	"shop/cmd/api/internal/services"
	"shop/cmd/api/internal/utils"
	"time"
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

	// If the group is for debug, add logger for easier development.
	if a.Conf.ApiConfig.IsDebug {
		app.Use(logger.New())
	}

	api := app.Group("/api/v1")
	if !a.Conf.ApiConfig.IsDebug {
		api.Use(limiter.New(limiter.Config{
			Max:        20,
			Expiration: 1 * time.Minute,
			LimitReached: func(c *fiber.Ctx) error {
				return c.JSON(utils.TooManyRequestsAPIError())
			},
		}))
	}

	middleware := jwtware.New(jwtware.Config{
		Claims: &auth.Claims{},
		SigningKey: jwtware.SigningKey{
			JWTAlg: jwt.SigningMethodHS256.Alg(),
			Key:    []byte(a.Conf.AuthConfig.JWTSecret),
		},
		SuccessHandler: func(c *fiber.Ctx) error {
			claims := c.Locals("user").(*jwt.Token).Claims.(*auth.Claims)
			c.Locals("user", claims)
			return c.Next()
		},
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			return c.Status(http.StatusUnauthorized).JSON(utils.InvalidTokenAPIError())
		},
	})

	// Group related to authentication.
	authGroup := api.Group("/auth")
	authGroup.Use(limiter.New(limiter.Config{
		Max:        3,
		Expiration: 1 * time.Minute,
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(http.StatusTooManyRequests).JSON(utils.TooManyRequestsAPIError())
		},
	}))
	authGroup.Post("/register", a.Handlers.UserHandler.RegisterClient())
	authGroup.Post("/login", a.Handlers.UserHandler.Login())
	authGroup.Get("/refresh", middleware, a.Handlers.UserHandler.RefreshSession())

	// Group related to admins used to manage users' data.
	adminGroup := api.Group("/admins")
	adminGroup.Use(middleware)
	adminGroup.Post("/register", a.Handlers.UserHandler.RegisterUser())
	adminGroup.Get("/usersInfo", a.Handlers.UserHandler.GetUsers())
	adminGroup.Get("/usersInfo/:id", a.Handlers.UserHandler.GetUserById())
	adminGroup.Get("/usersInfoByEmail/:email", a.Handlers.UserHandler.GetUserByEmail())
	adminGroup.Get("/usersInfoByUsername/:username", a.Handlers.UserHandler.GetUserByUsername())
	adminGroup.Delete("/deleteUser/:id", a.Handlers.UserHandler.DeleteUser())
	adminGroup.Patch("/forceLogout/:id", a.Handlers.UserHandler.ForceLogoutUser())
	adminGroup.Patch("/updateEmail", a.Handlers.UserHandler.UpdateUserEmail())
	adminGroup.Patch("/updateUsername", a.Handlers.UserHandler.UpdateUserUsername())

	return app.Listen(a.Conf.ApiConfig.ServerAddr)
}

// newAPI create a newAPI instance of API.
func newAPI() *API {
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
					repositories.NewPostgresTokenRepository(db),
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

	app := newAPI()
	err = app.start()
	log.Fatalf("Error starting the API with error: %v and configration: %+v", err, app.Conf)
}
