package auth

import (
	"authservice/pkg/tokens"
	"fmt"
	"testing"
	"time"
)

func TestCalculateAccessTokenHash(t *testing.T) {
	token := tokens.NewAccessToken(time.Now())

	secret := "my interesting secret"

	hash, err := CalculateAccessTokenHash(token, secret)

	if err != nil {
		t.Fatalf("%v", err)
	}

	if len(hash) == 0 {
		t.Fatalf("hash was not generated properly, result is ''")
	}

	fmt.Printf("hash is: %v", hash)
}

func TestSignAccessToken(t *testing.T) {
	token := tokens.NewAccessToken(time.Now())
	secret := "my inrerecting token"

	signature, err := CalculateAccessTokenHash(token, secret)

	if err != nil {
		t.Fatal(err)
	}

	SignAccessToken(&token, secret)

	if err != nil {
		t.Fatal(err)
	}

	if token.Signature != signature {
		t.Fatalf("signatures CalculateAccessTokenHash(token, secret) and SignAccessToken(&token, secret) are not equal: %v  ====  %v",
			signature, token.Signature)
	}
}
