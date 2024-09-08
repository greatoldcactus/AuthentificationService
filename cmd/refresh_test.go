package main

import (
	api "authservice/pkg/api"
	"authservice/pkg/mail"
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

	ip := "127.0.0.1"
	tokens, err := generateAccessRefreshPair(ip)

	requestBody, err := json.Marshal(tokens)

	if err != nil {
		t.Fatal(err)
	}

	request, err := http.NewRequest(http.MethodPost, "/v1/auth", bytes.NewBuffer(requestBody))
	request.RemoteAddr = ip

	if err != nil {
		t.Fatal(err)
	}

	request.Header.Add("Guid", "hello")

	var mailer mail.Mailer = &dummyMailer{}

	handler := http.HandlerFunc(newHandleRefresh(DB, mailer))

	handler.ServeHTTP(recorder, request)

	if mailer.(*dummyMailer).cnt > 0 {
		t.Fatal("request with equal ip must not cause mail warning")
	}

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

	handler := http.HandlerFunc(newHandleRefresh(DB, mailer))

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

	handler := http.HandlerFunc(newHandleRefresh(DB, mailer))

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

	handler := http.HandlerFunc(newHandleRefresh(DB, mailer))

	handler.ServeHTTP(recorder, request)

	response := recorder.Result()

	if response.StatusCode == 200 {
		t.Fatalf("Passed wrong request with incorrect method")
	}
}

type dummyMailer struct {
	cnt int
}

func (m *dummyMailer) SendWarning(from, to string, msg string) {
	fmt.Printf("new message from: %v, to: %v, content: %v", from, to, msg)
	m.cnt++
}

func TestRefreshIpChanged(t *testing.T) {

	recorder := httptest.NewRecorder()

	tokens, err := generateAccessRefreshPair("127.0.0.1")

	requestBody, err := json.Marshal(tokens)

	if err != nil {
		t.Fatal(err)
	}

	request, err := http.NewRequest(http.MethodPost, "/v1/auth", bytes.NewBuffer(requestBody))

	request.RemoteAddr = "another addr"

	if err != nil {
		t.Fatal(err)
	}

	if err != nil {
		t.Fatal(err)
	}

	request.Header.Add("Guid", "hello")

	var mailer mail.Mailer = &dummyMailer{}

	handler := http.HandlerFunc(newHandleRefresh(DB, mailer))

	handler.ServeHTTP(recorder, request)

	if mailer.(*dummyMailer).cnt == 0 {
		t.Fatalf("message must be sent!")
	}

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

func TestRefreshTokenExpired(t *testing.T) {

	recorder := httptest.NewRecorder()

	tokens, err := generateAccessRefreshPair("")

	requestBody, err := json.Marshal(tokens)

	if err != nil {
		t.Fatal(err)
	}

	request, err := http.NewRequest(http.MethodPost, "/v1/auth", bytes.NewBuffer(requestBody))

	request.RemoteAddr = ""

	if err != nil {
		t.Fatal(err)
	}

	if err != nil {
		t.Fatal(err)
	}

	request.Header.Add("Guid", "hello")

	var mailer mail.Mailer = &dummyMailer{}

	handler := http.HandlerFunc(newHandleRefresh(DB, mailer))

	handler.ServeHTTP(recorder, request)

	if mailer.(*dummyMailer).cnt == 0 {
		t.Fatalf("message must be sent!")
	}

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
