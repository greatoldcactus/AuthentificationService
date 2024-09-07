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

