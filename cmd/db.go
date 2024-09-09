package main

import (
	"database/sql"
	"fmt"
	"os"
	"time"

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

type DBProvider interface {
	QueryRow(query string, args ...any) *sql.Row
	Exec(query string, args ...any) (sql.Result, error)
}

// CheckRefreshTokenHash checks that Refresh token hash is contained in DB
func GetSessionHash(DB DBProvider, session string) (string, error) {

	row := DB.QueryRow("SELECT session_id, token_hash FROM sessions WHERE session_id = $1", session)

	var sessionId, resultHash string

	if err := row.Scan(&sessionId, &resultHash); err != nil {
		return "", fmt.Errorf("failed to get refresh token hash for session: %v, got error: %v", session, err)
	}

	return resultHash, nil
}

// AddRefreshTokenHash stores Refresh token hash to DB
func AddSession(DB DBProvider, hash string, GUID string, session string, expires time.Time) error {
	_, err := DB.Exec("INSERT INTO sessions (session_id, GUID, token_hash, expires_at) VALUES ($1, $2, $3, $4)", session, GUID, hash, expires)

	if err != nil {
		return fmt.Errorf("failed to add session: %v, got error: %v", session, err)
	}

	return nil
}

// AddRefreshTokenHash stores Refresh token hash to DB
func UpdateSession(DB DBProvider, hash string, session string, expires time.Time) error {
	_, err := DB.Exec("UPDATE sessions SET token_hash = $1, expires_at = $2 WHERE session_id = $3", hash, expires, session)

	if err != nil {
		return fmt.Errorf("failed to update session: %v, got error: %v", session, err)
	}

	return nil
}
