package main

import (
	api "authservice/pkg/api"
	"authservice/pkg/auth"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
)

func generateAccessRefreshTokens(ip string, session string) (accessToken api.AccessToken, refreshToken api.RefreshToken, err error) {
	accessToken = api.NewAccessToken(time.Now().Add(AccessTokenDuration), session)

	err = auth.SignAccessToken(&accessToken, secret)

	if err != nil {
		err = fmt.Errorf("failed to sign Access token when Refresh Access token pair generation: %w", err)
		return
	}

	refreshToken = api.NewRefreshToken(accessToken.Signature, time.Now().Add(RefreshTokenDuration), ip)

	return accessToken, refreshToken, nil
}

func makeTokenPair(accessToken api.AccessToken, refreshToken api.RefreshToken) (tokenPair api.RefreshAccessTokenPair, err error) {
	refreshTokenBase64, err := refreshToken.Base64()

	tokenPair = api.RefreshAccessTokenPair{
		RefreshToken: refreshTokenBase64,
		AccessToken:  accessToken,
	}

	return
}

func generateAccessRefreshPair(ip string, session string) (tokenPair api.RefreshAccessTokenPair, err error) {
	accessToken, refreshToken, err := generateAccessRefreshTokens(ip, session)

	if err != nil {
		err = fmt.Errorf("Refresh token base64 encoding error when Refresh Access token pair generation: %w", err)
		return
	}

	tokenPair, err = makeTokenPair(accessToken, refreshToken)
	return
}

func validateAuthRequest(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		msg := "must use POST"
		w.WriteHeader(http.StatusBadRequest)
		log.Default().Println(msg)
		w.Write([]byte(msg))
		return fmt.Errorf(msg)
	}

	GUIDs, ok := r.Header["Guid"]

	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		msg := "no GUID in request"
		log.Default().Println(msg)
		w.Write([]byte(msg))
		return fmt.Errorf(msg)
	}

	if len(GUIDs) > 1 {
		w.WriteHeader(http.StatusBadRequest)
		msg := "too much GUID in request"
		log.Default().Println(msg)
		w.Write([]byte(msg))
		return fmt.Errorf(msg)
	}

	return nil
}

func newHandleAuth(DB *sql.DB) func(w http.ResponseWriter, r *http.Request) {

	return func(w http.ResponseWriter, r *http.Request) {

		if err := validateAuthRequest(w, r); err != nil {
			return
		}

		GUID := r.Header.Get("Guid")
		session := uuid.New().String()

		ip := r.RemoteAddr

		accessToken, refreshToken, err := generateAccessRefreshTokens(ip, session)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Default().Printf("error when trying to generate Refresh Access token pair: %v\n", err)
			return
		}

		hash, err := refreshToken.Hash(GUID)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Default().Printf("error when trying to calculate hash for refresh token: %v\n", err)
			return
		}

		tx, err := DB.Begin()

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Default().Printf("error when trying to begin transaction: %v\n", err)
			return
		}

		defer func() {
			if err != nil {
				tx.Rollback()
			}
		}()

		err = AddSession(tx, hash, GUID, session, refreshToken.Header.Expires)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Default().Printf("error when trying to add new session: %v\n", err)
			return
		}

		tokenPair, err := makeTokenPair(accessToken, refreshToken)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Default().Printf("error when trying to make token pair: %v\n", err)
			return
		}

		answerJson, err := json.Marshal(tokenPair)

		if err != nil {
			log.Default().Println("auth answer json marshalling error error: ", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if err = tx.Commit(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Default().Printf("error when trying to commit new session: %v\n", err)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(answerJson)
	}
}
