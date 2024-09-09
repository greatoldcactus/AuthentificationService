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
	"sync"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type testDataRefresh struct {
	ChangeIP          bool
	MustFail          bool
	DBHasNotToken     bool
	WrongHash         bool
	GUID              []string
	Name              string
	ChangeAccessToken bool
	ChangeGuid        bool
	MustMail          bool
	WrongSession      bool
	Method            string
	TokenExpired      bool
}

func runRefreshTest(test testDataRefresh) error {
	ip := "127.0.0.1"

	session := ""

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

	var guid string
	if len(test.GUID) > 0 {
		guid = test.GUID[0]
	} else {
		guid = "guid"
	}

	if !test.ChangeGuid {
		request.Header["Guid"] = test.GUID
	} else {
		request.Header.Set("Guid", "changed GUID")
	}

	request.Method = test.Method

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
			hash, err = refreshToken.Hash(guid)

			if err != nil {
				return err
			}
		}

		fmt.Println("used hash: ", hash)

		err = AddSession(DB, hash, guid, session, refreshToken.Header.Expires)
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
			GUID:      []string{"hello"},
			Name:      "Ok",
			MustFail:  false,
			WrongHash: false,
			Method:    http.MethodPost,
		}, testDataRefresh{
			GUID:      []string{},
			Name:      "No GUID",
			MustFail:  true,
			WrongHash: false,
			Method:    http.MethodPost,
		}, testDataRefresh{
			GUID:      []string{"hello", "there"},
			Name:      "Too much GUID",
			MustFail:  true,
			WrongHash: false,
			Method:    http.MethodPost,
		}, testDataRefresh{
			GUID:      []string{"hello"},
			Name:      "Invalid method",
			MustFail:  true,
			WrongHash: false,
			Method:    http.MethodGet,
		}, testDataRefresh{
			GUID:      []string{"hello"},
			Name:      "Must post",
			MustFail:  false,
			WrongHash: false,
			MustMail:  true,
			ChangeIP:  true,
			Method:    http.MethodPost,
		}, testDataRefresh{
			GUID:         []string{"hello"},
			Name:         "Wrong session",
			MustFail:     true,
			WrongHash:    false,
			WrongSession: true,
			Method:       http.MethodPost,
		},
	}

	for _, test := range tests {
		mt := &sync.Mutex{}
		t.Run(test.Name, func(t *testing.T) {
			// Locking is necessary because the SQLite in-memory database can only have one instance;
			// Concurrent tests will cause failures otherwise.
			mt.Lock()
			defer mt.Unlock()
			err := runRefreshTest(test)
			if err != nil {
				t.Logf("Test %v failed with error: %v", test.Name, err)
				t.Fail()
			}
		})
	}
}

type dummyMailer struct {
	cnt int
}

func (m *dummyMailer) SendWarning(from, to string, msg string) {
	fmt.Printf("new message from: %v, to: %v, content: %v", from, to, msg)
	m.cnt++
}
