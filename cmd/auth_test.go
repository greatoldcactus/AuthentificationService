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

	request.Header.Add("guid", "hello")

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
