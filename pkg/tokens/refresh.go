package tokens

import "time"

// RefreshToken is used to Refresh Access token
type RefreshToken struct {
	Payload RefreshTokenPayload `json:"payload"`
}

// RefreshTokenPayload is payload for Refresh token
// Contains signature of AccessToken to be used with
type RefreshTokenPayload struct {
	AccessTokenSignature string `json:"accTokenSignature"`
}

// RefreshTokenHeader is header for Refresh token
type RefreshTokenHeader struct {
	Expires time.Time `json:"exp"`
}
