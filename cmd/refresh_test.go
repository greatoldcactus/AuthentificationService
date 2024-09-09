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
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type testDataRefresh struct {
	ChangeIP          bool
	MustFail          bool
	DBHasNotToken     bool
	WrongHash         bool
	GUID              string
	Name              string
	ChangeAccessToken bool
	ChangeGuid        bool
	MustMail          bool
	WrongSession      bool
}

func runRefreshTest(test testDataRefresh) error {
	ip := "127.0.0.1"

	session := ""

	// TODO add wrong session check

	tokens, err := generateAccessRefreshPair(ip, session)

	if test.WrongSession {
		session = "*"
	}

	if err != nil {
		return err
	}

	if test.ChangeIP {
		ip = "0.0.0.1"
	}

	if test.ChangeAccessToken {
		tokens.AccessToken.Header.Exp = tokens.AccessToken.Header.Exp.Add(time.Hour)
	}

	requestBody, err := json.Marshal(tokens)

	if err != nil {
		return err
	}

	request, err := http.NewRequest(http.MethodPost, "/v1/auth", bytes.NewBuffer(requestBody))
	request.RemoteAddr = ip

	if !test.ChangeGuid {
		request.Header.Set("Guid", test.GUID)
	} else {
		request.Header.Set("Guid", "not "+test.GUID)
	}

	var mailer mail.Mailer = &dummyMailer{}

	DB, err := CreateTestingBD()
	if err != nil {
		return err
	}
	defer DB.Close()

	if !test.DBHasNotToken {

		hash := "wrong hash"

		refreshToken, err := api.LoadRefreshTokenFromBase64(tokens.RefreshToken)

		if err != nil {
			return err
		}

		if !test.WrongHash {
			hash, err = refreshToken.Hash(test.GUID)

			if err != nil {
				return err
			}
		}

		fmt.Println("used hash: ", hash)

		err = AddSession(DB, hash, test.GUID, session, refreshToken.Header.Expires)
		if err != nil {
			return err
		}
	}

	handler := http.HandlerFunc(newHandleRefresh(DB, mailer))

	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if mailer.(*dummyMailer).cnt != 0 {
		if !test.MustMail {
			return fmt.Errorf("Ip was not changed, must not send mail warning!")
		}
	} else {
		if test.MustMail {
			return fmt.Errorf("Ip was not changed, must send mail warning!")
		}
	}

	response := recorder.Result()

	if response.StatusCode != 200 {
		if !test.MustFail {
			return fmt.Errorf("Test response status code expected to be 200, got: %v", response.Status)
		} else {
			return nil
		}
	} else if test.MustFail {
		return fmt.Errorf("Test response status code expected to be not 200, got: %v", response.Status)
	}

	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)

	if err != nil {
		return err
	}

	var tokensResult api.RefreshAccessTokenPair

	err = json.Unmarshal(responseBody, &tokensResult)

	if err != nil {
		return err
	}

	fmt.Printf("%#v", tokensResult)

	return nil

}

func TestRefresh(t *testing.T) {

	tests := []testDataRefresh{
		testDataRefresh{
			GUID:      "hello",
			Name:      "Ok",
			MustFail:  false,
			WrongHash: false,
		},
	}

	for _, test := range tests {
		err := runRefreshTest(test)
		if err != nil {
			t.Logf("Test %v failed with error: %v", test.Name, err)
			t.Fail()
		}
	}
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

	tokens, err := generateAccessRefreshPair("127.0.0.1", "")

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

	tokens, err := generateAccessRefreshPair("", "")

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
