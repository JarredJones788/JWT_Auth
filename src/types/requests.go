package types

//Login - details required to login
type Login struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	DeviceID string
}

//GetAccountsRequest - type of account wanted
type GetAccountsRequest struct {
	Roles []int `json:"roles"`
}

//DeleteAccountRequest - Id of the account being deletes
type DeleteAccountRequest struct {
	ID string `json:"id"`
}

//ActivateDevice - device activation struct
type ActivateDevice struct {
	Code     string
	DeviceID string
}

//RecoveryRequest - struct for creating a recovery request
type RecoveryRequest struct {
	Email string `json:"email"`
}

//FinalRecoveryRequest - struct for finishing a recovery
type FinalRecoveryRequest struct {
	ID       string `json:"id"`
	Password string `json:"password"`
}

//VerifyBrokerRequest - struct to verifiy a broker
type VerifyBrokerRequest struct {
	License string `json:"license"`
}

//UpdateAccountPassword - struct to update account password
type UpdateAccountPassword struct {
	OldPassword string `json:"oldPassword"`
	NewPassword string `json:"newPassword"`
}
