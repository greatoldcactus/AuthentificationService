package tokens

import "time"

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

