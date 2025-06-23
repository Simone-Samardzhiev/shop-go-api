package main

import (
	"api/auth"
	"api/config"
	"api/database"
	"api/handlers"
	"api/repositories"
	"api/services"
	"api/utils"
	jwtware "github.com/gofiber/contrib/jwt"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"log"
	"net/http"
)

// api struct contains the application.
type api struct {
	// Conf stores the configuration of the app.
	Conf     *config.Config
	Handlers handlers.Handlers
}

// start mounts the handlers and binds the app to the specified port.
func (a *api) start() error {
	app := fiber.New()

	// If the group is for debug, add logger for easier development.
	if a.Conf.ApiConfig.IsDebug {
		app.Use(logger.New())
	}

	group := app.Group("/group/v1")
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

	// Router related to users
	userGroup := group.Group("/users")
	userGroup.Post("/register/client", a.Handlers.UserHandler.RegisterClient())
	userGroup.Post("/login", a.Handlers.UserHandler.Login())
	// Handlers that require authentication
	userGroup.Use(middleware)
	userGroup.Post("/register/admin", a.Handlers.UserHandler.RegisterUser())
	userGroup.Get("/refresh", a.Handlers.UserHandler.RefreshSession())
	userGroup.Get("/usersInfo", a.Handlers.UserHandler.GetUsers())
	userGroup.Get("/userInfo/:id", a.Handlers.UserHandler.GetUserById())
	userGroup.Patch("/updateUser", a.Handlers.UserHandler.UpdateUser())

	return app.Listen(a.Conf.ApiConfig.ServerAddr)
}

// newAPI create a newAPI instance of api.
func newAPI() *api {
	conf := config.NewConfig()
	db, err := database.Connect(conf.DbConfig)
	if err != nil {
		log.Fatalf("Error connecting to database: %v", err)
	}

	return &api{
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
	log.Fatalf("Error starting the api with error: %v and configration: %+v", err, app.Conf)
}
