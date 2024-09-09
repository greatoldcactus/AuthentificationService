package tokens

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
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

// calcSHA256Cut calculates a SHA-256 hash for the token, truncating it to 72 bytes.
// The process involves marshaling the token to JSON, hashing it, and appending a GUID.
func (t RefreshToken) calcSHA256Cut(guid string) ([]byte, error) {
	jsonData, err := json.Marshal(t)

	if err != nil {
		return nil, fmt.Errorf("failed to marshall RefreshToken: %w", err)
	}

	shaHasher := sha256.New()

	if _, err = shaHasher.Write(jsonData); err != nil {
		return nil, fmt.Errorf("failed to calculate sha256 hash of RefreshToken json: %w", err)
	}

	if _, err = shaHasher.Write([]byte(guid)); err != nil {
		return nil, fmt.Errorf("failed to calculate sha256 hash of RefreshToken json: %w", err)
	}

	hash := shaHasher.Sum(nil)

	// Truncate hash to use it with bcrypt which has limit of 72 bytes
	if len(hash) > 72 {
		hash = hash[:72]
	}

	return hash, nil
}

// Hash computes a bcrypt hash of the RefreshToken using the provided GUID.
func (t RefreshToken) Hash(guid string) (string, error) {

	shaHash, err := t.calcSHA256Cut(guid)

	if err != nil {
		return "", err
	}

	hash, err := bcrypt.GenerateFromPassword(shaHash, bcrypt.DefaultCost)

	if err != nil {
		return "", fmt.Errorf("failed to calculate bcrypt hash for refresh token: %w", err)
	}

	return base64.StdEncoding.EncodeToString(hash), nil
}

// Verify checks if the provided hash matches the hash of the current RefreshToken.
func (t RefreshToken) Verify(guid string, hash string) (bool, error) {
	shaHash, err := t.calcSHA256Cut(guid)

	if err != nil {
		return false, err
	}

	decodedHash, err := base64.StdEncoding.DecodeString(hash)

	err = bcrypt.CompareHashAndPassword(decodedHash, shaHash)

	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return false, nil
		}
		return false, err
	}

	return true, nil
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
