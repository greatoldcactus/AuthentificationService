package main

import (
	"authservice/pkg/mail"
	"fmt"
	"net/http"
	"os"
	"time"
)

var secret string

const MinSecretLength int = 16
const AccessTokenDuration time.Duration = time.Hour * 2
const RefreshTokenDuration time.Duration = time.Hour * 24 * 30

var mailer mail.Mailer = mail.SimpleMailer{}

func main() {
	secret = os.Getenv("SECRET")

	if len(secret) < MinSecretLength {
		msg := fmt.Sprintf("Secret is too short: %v, expected at least: %v bytes", len(secret), MinSecretLength)
		panic(msg)
	}

	if err := ConnectDB(); err != nil {
		panic(err)
	}

	http.HandleFunc("/v1/auth", handleAuth)

	http.HandleFunc("/v1/refresh", handleRefresh)

	http.ListenAndServe(":5555", nil)
}
