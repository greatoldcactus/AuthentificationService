package tokens

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
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
	Ip                   string `json:"source_ip"`
}

// RefreshTokenHeader is header for Refresh token
type RefreshTokenHeader struct {
	Expires time.Time `json:"exp"`
}

// NewRefreshToken creates new refresh token
func NewRefreshToken(accessTokenSignature string, expires time.Time, ip string) RefreshToken {
	return RefreshToken{
		Payload: RefreshTokenPayload{
			AccessTokenSignature: accessTokenSignature,
			Ip:                   ip,
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

// Hash method is used to compute bcrypt hash of RefreshToken
func (t RefreshToken) Hash(guid string) (string, error) {

	json, err := json.Marshal(t)

	if err != nil {
		return "", fmt.Errorf("failed to marshall RefreshToken: %w", err)
	}

	shaHasher := sha256.New()

	if _, err = shaHasher.Write(json); err != nil {
		return "", fmt.Errorf("failed to calculate sha256 hash of RefreshToken json: %w", err)
	}

	if _, err = shaHasher.Write([]byte(guid)); err != nil {
		return "", fmt.Errorf("failed to calculate sha256 hash of RefreshToken json: %w", err)
	}

	hash := shaHasher.Sum(nil)

	// Truncate hash to use it with bcrypt which has limit of 72 bytes
	if len(hash) > 72 {
		hash = hash[:72]
	}

	hash, err = bcrypt.GenerateFromPassword(hash, bcrypt.DefaultCost)

	if err != nil {
		return "", fmt.Errorf("failed to calculate bcrypt hash for refresh token: %w", err)
	}

	return base64.StdEncoding.EncodeToString(hash), nil
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
