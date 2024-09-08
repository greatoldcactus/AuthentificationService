package main

import (
	"net/http"
	"time"
)

// TODO add loading from environment?
var secret string = "my secret"

const AccessTokenDuration time.Duration = time.Hour * 2
const RefreshTokenDuration time.Duration = time.Hour * 24 * 30

func main() {
	http.HandleFunc("/v1/auth", handleAuth)

	http.HandleFunc("/v1/refresh", handleRefresh)

	http.ListenAndServe(":5555", nil)
}
