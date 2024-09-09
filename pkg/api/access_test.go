package tokens

import (
	"fmt"
	"testing"
	"time"
)

func TestNewAccessTokenCreation(t *testing.T) {
	token := NewAccessToken(time.Now(), "session")

	fmt.Printf("token: %#v", token)

	if token.Header.Type != "JWT" {
		t.Errorf("expected Header.Type to be 'JWT', Header.Type is '%s'", token.Header.Type)
	}
	if token.Header.Alg != "SHA512" {
		t.Errorf("expected Header.Alg to be 'SHA512', Header.Alg is '%s'", token.Header.Alg)
	}
}
