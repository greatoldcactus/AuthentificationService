package tokens

import "time"

type RefreshToken struct {
	Payload RefreshTokenPayload `json:"payload"`
}

type RefreshTokenPayload struct {
	AccessTokenSignature string `json:"accTokenSignature"`
}

type RefreshTokenHeader struct {
	Expires time.Time `json:"exp"`
}
