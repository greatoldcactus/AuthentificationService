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
