package main

import (
	api "authservice/pkg/api"
	"authservice/pkg/auth"
	"authservice/pkg/mail"
	"database/sql"
	"encoding/json"
	"errors"
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

		if err != nil {
			log.Printf("error starting transaction: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		defer func() {
			if err != nil {
				tx.Rollback()
			}
		}()

		session := p.AccessToken.Payload.Session

		hash, err := GetSessionHash(tx, session)

		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				log.Printf("Refrsh token hash not found")
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("session not found"))
				return
			} else {
				log.Printf("error when trying to check refresh token hash in database: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

		}

		ok, err := refreshToken.Verify(GUID, hash)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Default().Printf("error when trying to check access token hash: %v", err)
			return
		}

		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			log.Default().Printf("incorrecr refresh token hash")
			w.Write([]byte("Incorrect hash"))
			return
		}

		newAccessToken, newRefreshToken, err := generateAccessRefreshTokens(ip, session)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Default().Printf("error when trying to generate Refresh Access token pair: %v", err)
			return
		}

		tokenPair, err := makeTokenPair(newAccessToken, newRefreshToken)

		if err != nil {
			log.Default().Println("failed to make token pair: ", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		answerJson, err := json.Marshal(tokenPair)

		if err != nil {
			log.Default().Println("auth answer json marshalling error error: ", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if err = UpdateSession(tx, requestHash, session, newRefreshToken.Header.Expires); err != nil {
			log.Default().Println("failed to update session: ", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if err = tx.Commit(); err != nil {
			log.Printf("error when committing transaction: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(answerJson)

	}
}
