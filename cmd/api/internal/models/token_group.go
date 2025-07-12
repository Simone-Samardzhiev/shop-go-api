package models

type TokenGroup struct {
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
}

// NewTokenGroup returns a new instance of TokenGroup
func NewTokenGroup(refreshToken, accessToken string) *TokenGroup {
	return &TokenGroup{
		RefreshToken: refreshToken,
		AccessToken:  accessToken,
	}
}
