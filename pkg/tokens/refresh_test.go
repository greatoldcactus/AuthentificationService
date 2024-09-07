package tokens

import (
	"testing"
	"time"
)

func TestNewRefreshToken(t *testing.T) {
	var _ RefreshToken = NewRefreshToken("hello", time.Now())
}

func TestRefreshToken_Base64(t *testing.T) {
	token := NewRefreshToken("hello", time.Now())

	tokenBase64, err := token.Base64()

	if err != nil {
		t.Fatalf("failed to encode Refresh token to base64: %v", err)
	}

	if tokenBase64 == "" {
		t.Fatalf("resulting Refresh token encoded to base64 string is empty")
	}
}

func TestLoadRefreshTokenFromBase64(t *testing.T) {
	token := NewRefreshToken("hello", time.Now())

	tokenBase64, err := token.Base64()

	if err != nil {
		t.Errorf("failed token base64 function")
	}

	tokenLoaded, err := LoadRefreshTokenFromBase64(tokenBase64)

	if err != nil {
		t.Errorf("failed to load token from base64 encoded string: %v", err)
	}

	if !tokenLoaded.Header.Expires.Equal(token.Header.Expires) {
		t.Errorf("loaded token time is not equal to initial token time:\n%#v\n%#v", tokenLoaded.Header.Expires, token.Header.Expires)
	}

	if tokenLoaded.Payload != token.Payload {
		t.Errorf("loaded token payload is not equal to initial token:\n%#v\n%#v", tokenLoaded.Payload, token.Payload)
	}
}

func TestRefreshToken_Hash(t *testing.T) {
	token := NewRefreshToken("hello", time.Now())

	hash, err := token.Hash()

	if err != nil {
		t.Fatal(err)
	}

	if hash == "" {
		t.Fatal("generated refresh token hash is empty!")
	}
}
