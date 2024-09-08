package main

import (
	api "authservice/pkg/api"
	"authservice/pkg/auth"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

func generateAccessRefreshPair() (tokenPair RefreshAccessTokenPair, err error) {
	accessToken := api.NewAccessToken(time.Now().Add(AccessTokenDuration))

	err = auth.SignAccessToken(&accessToken, secret)

	if err != nil {
		err = fmt.Errorf("failed to sign Access token when Refresh Access token pair generation: %w", err)
		return
	}

	refreshToken := api.NewRefreshToken(accessToken.Signature, time.Now().Add(RefreshTokenDuration))

	refreshTokenBase64, err := refreshToken.Base64()

	if err != nil {
		err = fmt.Errorf("Refresh token base64 encoding error when Refresh Access token pair generation: %w", err)
		return
	}

	tokenPair = RefreshAccessTokenPair{
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

func handleAuth(w http.ResponseWriter, r *http.Request) {

	if err := validateAuthRequest(w, r); err != nil {
		return
	}

	// GUID := r.Header.Get("Guid")
	// addr := r.RemoteAddr
	// TODO Add GUID to Refresh token hash calculation to ensure is was used by correct one
	// TODO add saving of Refresh tokens to DB

	tokenPair, err := generateAccessRefreshPair()

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

	w.Write(answerJson)
}
