package types

import "signer"

//GenericResponse - Simple response
type GenericResponse struct {
	Response bool `json:"response"`
}

//LoginResponse - struct for good login response
type LoginResponse struct {
	DeviceActive bool
	DeviceID     string
	Tokens       *signer.SignedResponse
}

//LoginResponseData - struct for good login response
type LoginResponseData struct {
	DeviceActive bool   `json:"deviceActive"`
	AccessToken  string `json:"accessToken"`
}

//AccessTokenResponse - returns access token
type AccessTokenResponse struct {
	AccessToken string `json:"accessToken"`
}

//AllUsersResponse - return success with data
type AllUsersResponse struct {
	Accounts *[]Account `json:"accounts"`
}

//ReasonResponse - return response with a reason
type ReasonResponse struct {
	Response bool   `json:"response"`
	Reason   string `json:"reason"`
}

//RecoveryResponse - return success with data
type RecoveryResponse struct {
	Response bool      `json:"response"`
	Data     *Recovery `json:"data"`
}

//ErrorResponse - returns an error response
type ErrorResponse struct {
	Error ErrorResponseBody `json:"error"`
}

//ErrorResponseBody - returns an error response
type ErrorResponseBody struct {
	HTTPStatusCode int    `json:"statusCode"`
	ErrorCode      int    `json:"errorCode"`
	ErrorMsg       string `json:"errorMsg"`
}
