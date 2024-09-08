package main

import (
	"database/sql"
	"fmt"
	"os"

	_ "github.com/lib/pq"
)

var DB *sql.DB

func ConnectDB() error {
	connectionInfo := os.Getenv("CONNECTION_STRING")

	if connectionInfo == "" {
		return fmt.Errorf("db connection string is empty")
	}

	db, err := sql.Open("postgres", connectionInfo)

	if err != nil {
		return fmt.Errorf("failed to connect db: %v", err)
	}

	DB = db

	return nil
}
