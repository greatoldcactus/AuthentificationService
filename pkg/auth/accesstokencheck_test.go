package auth

import (
	api "authservice/pkg/api"
	"fmt"
	"testing"
	"time"
)

func TestCalculateAccessTokenHash(t *testing.T) {
	token := api.NewAccessToken(time.Now(), "session")

	secret := "my interesting secret"

	hash, err := CalculateAccessTokenHash(token, secret)

	if err != nil {
		t.Fatalf("%v", err)
	}

	if len(hash) == 0 {
		t.Fatalf("hash was not generated properly, result is ''")
	}

	token.Signature = "hello there"

	hash2, err := CalculateAccessTokenHash(token, secret)

	if err != nil {
		t.Fatalf("%v", err)
	}

	if hash != hash2 {
		t.Fatalf("token hash was changed after signature was updated: %v    %v", hash, hash2)
	}

	fmt.Printf("hash is: %v", hash)
}

func TestSignAccessToken(t *testing.T) {
	token := api.NewAccessToken(time.Now(), "session")
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
