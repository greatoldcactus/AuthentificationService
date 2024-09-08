package main

import (
	"authservice/pkg/auth"
	"authservice/pkg/tokens"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// TODO add loading from environment?
var secret string = "my secret"

// RefreshAccessTokenPair is
type RefreshAccessTokenPair struct {
	AccessToken  tokens.AccessToken `json:"access_token"`
	RefreshToken string             `json:"refresh_token"`
}

const AccessTokenDuration time.Duration = time.Hour * 2
const RefreshTokenDuration time.Duration = time.Hour * 24 * 30

func generateAccessRefreshPair() (tokenPair RefreshAccessTokenPair, err error) {
	accessToken := tokens.NewAccessToken(time.Now().Add(AccessTokenDuration))

	err = auth.SignAccessToken(&accessToken, secret)

	if err != nil {
		err = fmt.Errorf("failed to sign Access token when Refresh Access token pair generation: %w", err)
		return
	}

	refreshToken := tokens.NewRefreshToken(accessToken.Signature, time.Now().Add(RefreshTokenDuration))

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

func handleAuth(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusBadRequest)
		log.Default().Println("incorrect request: must use POST")
		w.Write([]byte("incorrect request: must use POST"))
		return
	}

	GUIDs, ok := r.Header["guid"]

	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		log.Default().Println("incorrect request: no GUID in request")
		w.Write([]byte("there is no GUID in request"))
		return
	}

	if len(GUIDs) > 1 {
		w.WriteHeader(http.StatusBadRequest)
		log.Default().Println("incorrect request: too much GUID in request")
		w.Write([]byte("too much GUID in request"))
		return
	}

	// GUID := GUIDs[0]
	// addr := r.RemoteAddr
	// TODO Add GUID to Refresh token hash calculation to ensure is was used by correct one
	// TODO add saving of Refresh tokens to DB

	tokenPair, err := generateAccessRefreshPair()

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Default().Println("error when trying to generate Refresh Access token pair: %v", err)
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

func main() {
	http.HandleFunc("/v1/auth", handleAuth)

	http.ListenAndServe(":5555", nil)
}
