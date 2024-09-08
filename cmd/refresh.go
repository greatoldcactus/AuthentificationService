package main

import (
	api "authservice/pkg/api"
	"authservice/pkg/auth"
	"authservice/pkg/mail"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

func newHandleRefresh(DB *sql.DB, mailer mail.Mailer) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		if err := validateAuthRequest(w, r); err != nil {
			return
		}

		GUID := r.Header.Get("Guid")
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

		if time.Now().After(refreshToken.Header.Expires) {
			msg := "passed expired refresh token"
			log.Default().Printf(msg)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(msg))
			return
		}

		// TODO add user email from DB
		if refreshToken.Payload.Ip != ip {
			msg := fmt.Sprintf("warning attempting token refresh from another IP.\nOld ip: %v\nNew ip: %v", refreshToken.Payload.Ip, ip)
			mailer.SendWarning("authwarning@example.com", "user@example.com", msg)
		}

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

		requestHash, err := refreshToken.Hash(GUID)

		if err != nil {
			log.Printf("error when calculating Refresh token hash: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		tx, err := DB.Begin()

		defer func() {
			if err != nil {
				tx.Rollback()
			}
		}()

		if err = CheckRefreshTokenHash(w, r, DB, requestHash); err != nil {
			return
		}

		if err = DeleteRefreshTokenHash(w, r, DB, requestHash); err != nil {
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

		if err = AddRefreshTokenHash(w, r, DB, requestHash, GUID); err != nil {
			return
		}

		if err = tx.Commit(); err != nil {
			log.Printf("error when committing transaction: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Write(answerJson)

	}
}
