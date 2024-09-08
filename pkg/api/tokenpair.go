package tokens

// RefreshAccessTokenPair is pair of Refresh and Access tokens that is used in Refresh and Auth request
type RefreshAccessTokenPair struct {
	AccessToken  AccessToken `json:"access_token"`
	RefreshToken string      `json:"refresh_token"`
}
