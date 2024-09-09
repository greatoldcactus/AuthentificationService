package main

import (
	api "authservice/pkg/api"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func CreateTestingBD() (*sql.DB, error) {
	DB, err := sql.Open("sqlite3", ":memory:")

	if err != nil {
		return nil, err
	}

	defer func() {
		if err != nil {
			DB.Close()
		}
	}()

	tx, err := DB.Begin()
	if err != nil {
		return nil, err
	}

	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	_, err = tx.Exec(`CREATE TABLE sessions (
		session_id TEXT PRIMARY KEY,
		GUID TEXT NOT NULL, 
		token_hash TEXT NOT NULL, 
		expires_at TIME)
		`)

	if err != nil {
		return nil, err
	}

	if err = tx.Commit(); err != nil {
		return nil, err
	}

	return DB, nil

}

func TestAuthOk(t *testing.T) {
	recorder := httptest.NewRecorder()
	request, err := http.NewRequest(http.MethodPost, "/v1/auth", strings.NewReader(""))

	if err != nil {
		t.Fatal(err)
	}

	guid := "hello"

	request.Header.Add("Guid", "hello")

	DB, err := CreateTestingBD()

	if err != nil {
		t.Fatal(err)
	}

	handler := http.HandlerFunc(newHandleAuth(DB))

	handler.ServeHTTP(recorder, request)

	response := recorder.Result()

	if response.StatusCode != 200 {
		t.Fatalf("Request failed with code: %v", response.Status)
	}

	responseBody, err := io.ReadAll(response.Body)

	if err != nil {
		t.Fatalf("Failed to read response body")
	}

	var tokens api.RefreshAccessTokenPair

	err = json.Unmarshal(responseBody, &tokens)

	if err != nil {
		t.Fatalf("failed to unmarshall answer from server: %v", err)
	}

	refreshToken, err := api.LoadRefreshTokenFromBase64(tokens.RefreshToken)

	if err != nil {
		t.Fatalf("failed to load Refresh token from base64: %v", err)
	}

	session := tokens.AccessToken.Payload.Session

	hash, err := GetSessionHash(DB, session)

	if err != nil {
		t.Fatalf("failed to get hash for session: %v, err: %v", session, err)
	}

	result, err := refreshToken.Verify(guid, hash)

	if err != nil {
		t.Fatalf("failed to verify refresh token: %v", err)
	}

	if !result {
		t.Fatalf("session was not saved")
	}

}

func TestAuthNoGuid(t *testing.T) {
	recorder := httptest.NewRecorder()
	request, err := http.NewRequest(http.MethodPost, "/v1/auth", strings.NewReader(""))

	if err != nil {
		t.Fatal(err)
	}

	DB, err := CreateTestingBD()

	if err != nil {
		t.Fatal(err)
	}
	handler := http.HandlerFunc(newHandleAuth(DB))

	handler.ServeHTTP(recorder, request)

	response := recorder.Result()

	if response.StatusCode == 200 {
		t.Fatalf("Passed wrong request with no GUID")
	}
}

func TestAuthTooMuchGuid(t *testing.T) {
	recorder := httptest.NewRecorder()
	request, err := http.NewRequest(http.MethodPost, "/v1/auth", strings.NewReader(""))

	request.Header.Add("Guid", "hello")
	request.Header.Add("Guid", "there")

	if err != nil {
		t.Fatal(err)
	}

	DB, err := CreateTestingBD()

	if err != nil {
		t.Fatal(err)
	}
	handler := http.HandlerFunc(newHandleAuth(DB))

	handler.ServeHTTP(recorder, request)

	response := recorder.Result()

	if response.StatusCode == 200 {
		t.Fatalf("Passed wrong request with too much GUID")
	}
}

func TestAuthInvalidMethod(t *testing.T) {
	recorder := httptest.NewRecorder()
	request, err := http.NewRequest(http.MethodGet, "/v1/auth", strings.NewReader(""))

	if err != nil {
		t.Fatal(err)
	}

	DB, err := CreateTestingBD()

	if err != nil {
		t.Fatal(err)
	}
	handler := http.HandlerFunc(newHandleAuth(DB))

	handler.ServeHTTP(recorder, request)

	response := recorder.Result()

	if response.StatusCode == 200 {
		t.Fatalf("Passed wrong request with incorrect method")
	}
}
