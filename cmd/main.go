package main

import (
	"authservice/pkg/tokens"
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

func main() {
	http.HandleFunc("/v1/auth", handleAuth)

	http.ListenAndServe(":5555", nil)
}
