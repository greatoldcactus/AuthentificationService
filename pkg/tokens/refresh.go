package tokens

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// RefreshToken is used to Refresh Access token
type RefreshToken struct {
	Payload RefreshTokenPayload `json:"payload"`
	Header  RefreshTokenHeader  `json:"header"`
}

// RefreshTokenPayload is payload for Refresh token
// Contains signature of AccessToken to be used with
type RefreshTokenPayload struct {
	AccessTokenSignature string `json:"access_token_signature"`
}

// RefreshTokenHeader is header for Refresh token
type RefreshTokenHeader struct {
	Expires time.Time `json:"exp"`
}

// NewRefreshToken creates new refresh token
func NewRefreshToken(accessTokenSignature string, expires time.Time) RefreshToken {
	return RefreshToken{
		Payload: RefreshTokenPayload{
			AccessTokenSignature: accessTokenSignature,
		},
		Header: RefreshTokenHeader{
			Expires: expires,
		},
	}
}

// RefreshToken.Base64 encodes RefreshToken in base64
func (t RefreshToken) Base64() (string, error) {
	tokenJson, err := json.Marshal(t)

	if err != nil {
		return "", fmt.Errorf("failed to marshall RefreshToken: %w", err)
	}

	return base64.StdEncoding.EncodeToString(tokenJson), nil
}

// LoadRefreshTokenFromBase64 loads Refresh token from base64 encoding
func LoadRefreshTokenFromBase64(s string) (RefreshToken, error) {

	if s == "" {
		return RefreshToken{}, fmt.Errorf("empty input string")
	}

	tokenJson, err := base64.StdEncoding.DecodeString(s)

	if err != nil {
		return RefreshToken{}, fmt.Errorf("incorrect Refresh token base64 string: %w", err)
	}

	var token RefreshToken

	err = json.Unmarshal(tokenJson, &token)

	if err != nil {
		return RefreshToken{}, fmt.Errorf("failed to unmarshall Refresh token from json: %w", err)
	}

	return token, nil
}
