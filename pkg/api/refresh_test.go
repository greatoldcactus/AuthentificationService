package tokens

import (
	"testing"
	"time"
)

func TestNewRefreshToken(t *testing.T) {
	var _ RefreshToken = NewRefreshToken("hello", time.Now(), "your ip")
}

func TestRefreshToken_Base64(t *testing.T) {
	token := NewRefreshToken("hello", time.Now(), "your ip")

	tokenBase64, err := token.Base64()

	if err != nil {
		t.Fatalf("failed to encode Refresh token to base64: %v", err)
	}

	if tokenBase64 == "" {
		t.Fatalf("resulting Refresh token encoded to base64 string is empty")
	}
}

func TestLoadRefreshTokenFromBase64(t *testing.T) {
	token := NewRefreshToken("hello", time.Now(), "your ip")

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

func TestRefreshToken_Verify(t *testing.T) {
	token := NewRefreshToken("hello", time.Now(), "your ip")

	GUID := "h"

	hash, err := token.Hash(GUID)

	if err != nil {
		t.Fatalf("failed to calculate token hash: %v", err)
	}

	if ok, err := token.Verify(GUID, hash); err != nil {
		t.Fatalf("failed to verify token hash: %v", err)
	} else {
		if !ok {
			t.Fatalf("token wasn't changed, but verify failed!")
		}
	}

	token.Payload.Ip += "!!!"

	if ok, err := token.Verify(GUID, hash); err == nil {
		t.Fatalf("token was changed, but Verify returned that it was equal!")
	} else {
		if ok {
			t.Fatalf("token was changed, but Verify returned that it was equal!")
		}
	}
}

func TestRefreshTokenHashChangeAfterLoad(t *testing.T) {

	token := NewRefreshToken("hello", time.Now(), "your ip")

	tokenBase64, err := token.Base64()

	if err != nil {
		t.Errorf("failed token base64 function")
	}

	tokenLoaded, err := LoadRefreshTokenFromBase64(tokenBase64)

	if err != nil {
		t.Errorf("failed to load token from base64 encoded string: %v", err)
	}

	guid := "g"

	hash1, err := token.Hash(guid)

	if err != nil {
		t.Errorf("failed to calculate token hash: %v", err)
	}

	if ok, err := tokenLoaded.Verify(guid, hash1); err != nil {
		t.Errorf("failed to verify token hash")
	} else {
		if !ok {
			t.Errorf("token hash was changed after loading!")
		}
	}
}

func TestRefreshToken_Hash(t *testing.T) {
	token := NewRefreshToken("hello", time.Now(), "your ip")

	hash, err := token.Hash("832")

	if err != nil {
		t.Fatal(err)
	}

	if hash == "" {
		t.Fatal("generated refresh token hash is empty!")
	}

	hash2, err := token.Hash("933")

	if err != nil {
		t.Fatal(err)
	}

	if hash == hash2 {
		t.Fatalf("token hash not differs with different GUID")
	}
}
