package main

import (
	api "authservice/pkg/api"
	"authservice/pkg/auth"
	"encoding/json"
	"io"
	"log"
	"net/http"
)

func handleRefresh(w http.ResponseWriter, r *http.Request) {

	if err := validateAuthRequest(w, r); err != nil {
		return
	}

	// GUID := r.Header.Get("Guid")
	ip := r.RemoteAddr

	body, err := io.ReadAll(r.Body)

	if err != nil {
		log.Default().Printf("failed to read all data from request body: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var p api.RefreshAccessTokenPair

	err = json.Unmarshal(body, &p)

	if err != nil {
		log.Default().Printf("failed to unmarshall RefreshAccessTokenPair from request: %v\n", err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("there is no Refresh Access token pair in request"))
		return
	}

	refreshToken, err := api.LoadRefreshTokenFromBase64(p.RefreshToken)

	if err != nil {
		log.Default().Printf("failed to load Refresh token from request: %v\n", err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("there is incorrect Refresh token in request"))
		return
	}

	// TODO add check for Refresh token signature

	accessToken := p.AccessToken

	accessTokenSignature, err := auth.CalculateAccessTokenHash(accessToken, secret)

	if err != nil {
		log.Default().Printf("failed to calculate Access token signature: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if accessToken.Signature != accessTokenSignature {
		log.Default().Printf("attempted to refresh with access token with incorrect signature: %v\n", err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("there is incorrect Refresh token in request"))
		return
	}

	if refreshToken.Payload.AccessTokenSignature != accessTokenSignature {
		log.Default().Printf("attempted to refresh with signature in refresh token not equal to signature of access token: %v\n", err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("there is incorrect Refresh token in request"))
		return
	}

	// TODO invalidate old Refresh token in DB

	tokenPair, err := generateAccessRefreshPair(ip)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Default().Printf("error when trying to generate Refresh Access token pair: %v", err)
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
