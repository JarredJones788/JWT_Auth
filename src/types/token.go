package types

import "time"

//RefreshToken - Refresh token struct
type RefreshToken struct {
	ID        string    `sql:"id" json:"id"`
	AccountID string    `sql:"accountId" json:"accountId"`
	DeviceID  string    `sql:"deviceId" json:"deviceId"`
	Created   time.Time `sql:"created" json:"created"`
}

//AuthTokens - AuthTokens struct
type AuthTokens struct {
	AccessToken  string
	RefreshToken string
}
