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
)

func generateAccessRefreshPair(ip string, session string) (tokenPair api.RefreshAccessTokenPair, err error) {
	accessToken := api.NewAccessToken(time.Now().Add(AccessTokenDuration), session)

	err = auth.SignAccessToken(&accessToken, secret)

	if err != nil {
		err = fmt.Errorf("failed to sign Access token when Refresh Access token pair generation: %w", err)
		return
	}

	refreshToken := api.NewRefreshToken(accessToken.Signature, time.Now().Add(RefreshTokenDuration), ip)

	refreshTokenBase64, err := refreshToken.Base64()

	if err != nil {
		err = fmt.Errorf("Refresh token base64 encoding error when Refresh Access token pair generation: %w", err)
		return
	}

	tokenPair = api.RefreshAccessTokenPair{
		RefreshToken: refreshTokenBase64,
		AccessToken:  accessToken,
	}

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

		// GUID := r.Header.Get("Guid")
		// TODO Add GUID to Refresh token hash calculation to ensure is was used by correct one
		// TODO add saving of Refresh tokens to DB

		ip := r.RemoteAddr

		tokenPair, err := generateAccessRefreshPair(ip, "")

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Default().Printf("error when trying to generate Refresh Access token pair: %v\n", err)
			return
		}

		answerJson, err := json.Marshal(tokenPair)

		if err != nil {
			log.Default().Println("auth answer json marshalling error error: ", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(answerJson)
	}
}
