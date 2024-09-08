package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
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

// CheckRefreshTokenHash checks that Refresh token hash is contained in DB
func CheckRefreshTokenHash(w http.ResponseWriter, r *http.Request, DB *sql.DB, hash string) error {
	row := DB.QueryRow("SELECT * FROM REFRESH_TOKEN WHERE token_hash = $1", hash)

	var resultHash string

	if err := row.Scan(&resultHash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			msg := "Invalid refresh token"
			log.Default().Print(msg)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(msg))
			return err
		}

		log.Default().Printf("failed to query row from db: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return err
	}

	return nil
}

// DeleteRefreshTokenHash deletes Refresh token hash from DB
func DeleteRefreshTokenHash(w http.ResponseWriter, r *http.Request, DB *sql.DB, hash string) error {
	_, err := DB.Exec("DELETE FROM REFRESH_TOKEN WHERE token_hash = $1", hash)

	if err != nil {
		log.Default().Printf("error when deleting token hash from DB: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return err
	}

	return nil
}

// AddRefreshTokenHash stores Refresh token hash to DB
func AddRefreshTokenHash(w http.ResponseWriter, r *http.Request, DB *sql.DB, hash string, GUID string) error {
	_, err := DB.Exec("INSERT INTO REFRESH_TOKEN (token_hash, GUID) VALUES ($1, $2)", hash, GUID)

	if err != nil {
		log.Printf("error when writing new refresh token hash into DB: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return err
	}

	return nil
}
