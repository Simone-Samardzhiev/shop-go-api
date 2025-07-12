package database

import (
	"database/sql"
	"shop/cmd/api/internal/config"
)

func Connect(config *config.DatabaseConfig) (*sql.DB, error) {
	db, err := sql.Open("postgres", config.URL)
	if err != nil {
		return nil, err
	}

	err = db.Ping()
	if err != nil {
		return nil, err
	}

	db.SetMaxIdleConns(config.MaxIdleConnections)
	db.SetMaxOpenConns(config.MaxOpenConnections)
	db.SetConnMaxIdleTime(config.MaxIdleTime)
	db.SetConnMaxLifetime(config.MaxLifetime)

	return db, nil
}
