package main

import (
	api "authservice/pkg/api"
	"net/http"
	"time"
)

// TODO add loading from environment?
var secret string = "my secret"

// RefreshAccessTokenPair is pair of Refresh and Access tokens that is used in Refresh and Auth request
type RefreshAccessTokenPair struct {
	AccessToken  api.AccessToken `json:"access_token"`
	RefreshToken string          `json:"refresh_token"`
}

const AccessTokenDuration time.Duration = time.Hour * 2
const RefreshTokenDuration time.Duration = time.Hour * 24 * 30

func main() {
	http.HandleFunc("/v1/auth", handleAuth)

	http.ListenAndServe(":5555", nil)
}
