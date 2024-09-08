package tokens

import "time"

// AccessToken is JWT token
type AccessToken struct {
	Signature string             `json:"signature"`
	Payload   AccessTokenPayload `json:"payload"`
	Header    AccessTokenHeader  `json:"header"`
}

// AccessTokenPayload is payload for AccessToken
// Currently empty
type AccessTokenPayload struct {
}

// Header for AccessToken
type AccessTokenHeader struct {
	Type string    `json:"typ"`
	Alg  string    `json:"alg"`
	Exp  time.Time `json:"exp"`
}

// NewAccessToken creates a new AccessToken with a specified expiration time.
func NewAccessToken(Exp time.Time) AccessToken {
	return AccessToken{
		Header: AccessTokenHeader{
			Type: "JWT",
			Alg:  "SHA512",
			Exp:  Exp,
		},
	}
}
