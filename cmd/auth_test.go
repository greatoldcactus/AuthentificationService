package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuthOk(t *testing.T) {
	recorder := httptest.NewRecorder()
	request, err := http.NewRequest(http.MethodPost, "/v1/auth", strings.NewReader(""))

	if err != nil {
		t.Fatal(err)
	}

	request.Header.Add("Guid", "hello")

	handler := http.HandlerFunc(handleAuth)

	handler.ServeHTTP(recorder, request)

	response := recorder.Result()

	if response.StatusCode != 200 {
		t.Fatalf("Request failed with code: %v", response.Status)
	}

	responseBody, err := io.ReadAll(response.Body)

	if err != nil {
		t.Fatalf("Failed to read response body")
	}

	var tokens RefreshAccessTokenPair

	err = json.Unmarshal(responseBody, &tokens)

	if err != nil {
		t.Fatalf("failed to unmarshall answer from server: %v", err)
	}

}

func TestAuthNoGuid(t *testing.T) {
	recorder := httptest.NewRecorder()
	request, err := http.NewRequest(http.MethodPost, "/v1/auth", strings.NewReader(""))

	if err != nil {
		t.Fatal(err)
	}

	handler := http.HandlerFunc(handleAuth)

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

	handler := http.HandlerFunc(handleAuth)

	handler.ServeHTTP(recorder, request)

	response := recorder.Result()

	if response.StatusCode == 200 {
		t.Fatalf("Passed wrong request with too much GUID")
	}
}

func TeshAuthInvalidMethod(t *testing.T) {
	recorder := httptest.NewRecorder()
	request, err := http.NewRequest(http.MethodGet, "/v1/auth", strings.NewReader(""))

	if err != nil {
		t.Fatal(err)
	}

	handler := http.HandlerFunc(handleAuth)

	handler.ServeHTTP(recorder, request)

	response := recorder.Result()

	if response.StatusCode == 200 {
		t.Fatalf("Passed wrong request with incorrect method")
	}
}
