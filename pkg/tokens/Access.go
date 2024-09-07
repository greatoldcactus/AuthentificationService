package tokens

import "time"

type AccessToken struct {
	Signature string             `json:"signature"`
	Payload   AccessTokenPayload `json:"payload"`
	Header    AccessTokenHeader  `json:"header"`
}

type AccessTokenPayload struct {
}

type AccessTokenHeader struct {
	Type string    `json:"typ"`
	Alg  string    `json:"alg"`
	Exp  time.Time `json:"exp"`
}

func NewAccessToken(Exp time.Time) AccessToken {
	return AccessToken{
		Header: AccessTokenHeader{
			Type: "JWT",
			Alg:  "SHA512",
			Exp:  Exp,
		},
	}
}
