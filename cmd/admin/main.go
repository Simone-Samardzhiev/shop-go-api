package main

import (
	"database/sql"
	"fmt"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"log"
)

func connectToDatabase() *sql.DB {
	var databaseURL string
	fmt.Println("Please provide the database url:")
	_, err := fmt.Scanln(&databaseURL)
	if err != nil {
		log.Fatalf("Error reading database url: %v", err)
	}

	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		log.Fatalf("Error opening database connection: %v", err)
	}
	err = db.Ping()
	if err != nil {
		log.Fatalf("Error pinging database connection: %v", err)
	}

	return db
}

func getEmail() string {
	var email string
	fmt.Println("Please provide the email address:")
	_, err := fmt.Scanln(&email)
	if err != nil {
		log.Fatalf("Error reading email address: %v", err)
	}
	return email
}

func getUsername() string {
	var username string
	fmt.Println("Please provide the user name:")
	_, err := fmt.Scanln(&username)
	if err != nil {
		log.Fatalf("Error reading user name: %v", err)
	}
	return username
}

func getPassword() string {
	var password string
	fmt.Println("Please provide the password:")
	_, err := fmt.Scanln(&password)
	if err != nil {
		log.Fatalf("Error reading password: %v", err)
	}

	return password
}

func main() {
	log.Println("Warning: CLI used to insert the root admin of the app")
	db := connectToDatabase()
	email := getEmail()
	username := getUsername()
	password := getPassword()

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("Error hashing password: %v", err)
	}

	_, err = db.Exec(`
		INSERT INTO users(id, email, username, password, user_role)
		VALUES($1, $2, $3, $4, $5)`,
		uuid.New().String(),
		email,
		username,
		hash,
		"admin",
	)

	if err != nil {
		log.Fatalf("Error inserting admin: %v", err)
	}

	log.Println("Successfully inserted admin")
}
