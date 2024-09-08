package main

import (
	api "authservice/pkg/api"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRefreshOk(t *testing.T) {
	recorder := httptest.NewRecorder()

	tokens, err := generateAccessRefreshPair("127.0.0.1")

	requestBody, err := json.Marshal(tokens)

	if err != nil {
		t.Fatal(err)
	}

	request, err := http.NewRequest(http.MethodPost, "/v1/auth", bytes.NewBuffer(requestBody))

	if err != nil {
		t.Fatal(err)
	}

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

	var tokensResult api.RefreshAccessTokenPair

	err = json.Unmarshal(responseBody, &tokensResult)

	if err != nil {
		t.Fatalf("failed to unmarshall answer from server: %v", err)
	}

	fmt.Printf("%#v", tokensResult)

}

func TestRefreshNoGuid(t *testing.T) {
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

func TestRefreshTooMuchGuid(t *testing.T) {
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

func TestRefreshInvalidMethod(t *testing.T) {
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
