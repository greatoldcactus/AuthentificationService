package auth

import (
	"authservice/pkg/tokens"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// CalculateAccessTokenHash calculates the hash of the given access token using the provided secret.
func CalculateAccessTokenHash(token tokens.AccessToken, secret string) (hash string, err error) {
	shaObject := sha512.New()

	payloadData, err := json.Marshal(token.Payload)

	if err != nil {
		return "", fmt.Errorf("incorrect payload for access token: %w", err)
	}

	shaObject.Write(payloadData)

	headerData, err := json.Marshal(token.Header)

	if err != nil {
		return "", fmt.Errorf("incorrect header for access token: %w", err)
	}

	shaObject.Write(headerData)

	shaObject.Write([]byte(secret))

	finalHash := shaObject.Sum(nil)

	hash = base64.StdEncoding.EncodeToString(finalHash)

	return
}

var ErrNilPointerToken error = errors.New("passed nil as *tokens.AccessToken")

// SignAccessToken sets the signature of the given access token using the hash calculated by CalculateAccessTokenHash.
func SignAccessToken(token *tokens.AccessToken, secret string) (err error) {

	if token == nil {
		return ErrNilPointerToken
	}

	signature, err := CalculateAccessTokenHash(*token, secret)

	if err != nil {
		return fmt.Errorf("incorrect token for signature calculation: %v", err)
	}

	token.Signature = signature

	return nil
}
