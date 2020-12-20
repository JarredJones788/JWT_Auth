package auth

import (
	"dao"
	"db"
	"email"
	"errors"
	"signer"
	"types"
	"utils"
)

//Authorize - Authorize class
type Authorize struct {
	DB      *db.MySQL
	Sign    *signer.JWTSigner
	Emailer *email.Emailer
}

//Init - Start Authorize service
func (auth Authorize) Init(jwt *signer.JWTSigner, db *db.MySQL, emailer *email.Emailer) *Authorize {
	auth.DB = db
	auth.Sign = jwt
	auth.Emailer = emailer
	return &auth
}

//CheckAccessToken - verifies access token is valid
func (auth Authorize) CheckAccessToken(tokens *types.AuthTokens) (*signer.AccessClaims, error) {
	result, err := auth.Sign.VerifyAccessToken(tokens.AccessToken)
	if err != nil {
		return nil, err
	}

	return result, nil
}

//RegisterAccount - register a new account
func (auth Authorize) RegisterAccount(tokens *types.AuthTokens, newAccount *types.Account) (string, error) {

	//Get newAccount Roles
	newAccount.GetAccountPermissions()

	res, err := dao.AccountDAO{}.CreateAccount(newAccount, auth.DB)
	if err != nil {
		return "", err
	}

	return res, nil
}

//DeleteAccount - deletes an account
func (auth Authorize) DeleteAccount(tokens *types.AuthTokens, del *types.DeleteAccountRequest) (string, error) {
	account, err := auth.CheckAccessToken(tokens)
	if err != nil {
		return "", err
	}

	//Only Accounts with ADMIN privliges can make this request
	if !utils.Contains("ADMIN", account.Roles) {
		return "", errors.New("Invalid Privilges: " + account.FirstName + " " + account.LastName)
	}

	delAccount, err := dao.AccountDAO{}.GetAccountByID(del.ID, auth.DB)
	if err != nil {
		return "", err
	}

	if delAccount == nil {
		return "", errors.New("No account found")
	}

	//Get roles of the account we are trying to delete
	delAccount.GetAccountPermissions()

	//DO delete checking here. If user requesting is allowed to delete this account

	err = dao.AccountDAO{}.DeleteAccount(delAccount, auth.DB)
	if err != nil {
		return "", err
	}

	return "", nil
}

//GetAccount - returns the account of the user requesting
func (auth Authorize) GetAccount(tokens *types.AuthTokens) (interface{}, error) {
	result, err := auth.CheckAccessToken(tokens)
	if err != nil {
		return nil, err
	}

	account, err := dao.AccountDAO{}.GetAccountByID(result.ID, auth.DB)
	if err != nil {
		return nil, err
	}

	//No account was found
	if account == nil {
		return nil, errors.New("no account was found")
	}

	account.GetAccountPermissions()
	account.HideImportant()

	return account, nil
}

//GetAccounts - returns accounts from the role given. role 0 will get all accounts
func (auth Authorize) GetAccounts(tokens *types.AuthTokens, roles []int) (*[]types.Account, error) {
	account, err := auth.CheckAccessToken(tokens)
	if err != nil {
		return nil, err
	}

	//Only Accounts with Admin privliges can make this request
	if !utils.Contains("ADMIN", account.Roles) {
		return nil, errors.New("Invalid Privilges: " + account.FirstName + " " + account.LastName)
	}

	accounts, err := dao.AccountDAO{}.GetAccounts(roles, auth.DB)
	if err != nil {
		return nil, err
	}

	return accounts, nil
}

//UpdateSettings - update requesting account settings
func (auth Authorize) UpdateSettings(tokens *types.AuthTokens, updatedAccount *types.Account) (string, error) {
	account, err := auth.CheckAccessToken(tokens)
	if err != nil {
		return "", err
	}

	res, err := dao.AccountDAO{}.UpdateSettings(updatedAccount, account.ID, auth.DB)
	if err != nil {
		return "", err
	}

	return res, nil
}

//UpdateAccount - update account settings for another user
func (auth Authorize) UpdateAccount(tokens *types.AuthTokens, updatedAccount *types.Account) (string, error) {
	account, err := auth.CheckAccessToken(tokens)
	if err != nil {
		return "", err
	}

	//Only Accounts with ADMIN privliges can make this request
	if !utils.Contains("ADMIN", account.Roles) {
		return "", errors.New("Invalid Privilges: " + account.FirstName + " " + account.LastName)
	}

	dao := dao.AccountDAO{}

	accountData, err := dao.GetAccountByID(updatedAccount.ID, auth.DB)
	if err != nil {
		return "", err
	}

	//No account was found
	if account == nil {
		return "", errors.New("no account was found")
	}

	//Get roles of the account we are trying to update
	accountData.GetAccountPermissions()

	//Check if requesting user can update this account type HERE

	accountData.FirstName = updatedAccount.FirstName
	accountData.LastName = updatedAccount.LastName
	accountData.Phone = updatedAccount.Phone
	accountData.Email = updatedAccount.Email
	accountData.Role = updatedAccount.Role

	if accountData.Role == 0 { //default role
		accountData.Role = 100
	}

	res, err := dao.UpdateAccount(accountData, auth.DB)
	if err != nil {
		return "", err
	}

	return res, nil
}

//ActivateDevice - activates a device for the requesting user.
func (auth Authorize) ActivateDevice(deviceActivation *types.ActivateDevice) error {

	device, err := dao.DeviceDAO{}.GetDevice(deviceActivation.DeviceID, auth.DB)
	if err != nil {
		return err
	}

	if device == nil {
		return errors.New("No device was found")
	}

	if device.Active {
		return errors.New("Device is already active")
	}

	if device.Code != deviceActivation.Code {
		return errors.New("Invalid Code")
	}

	//Activate device
	err = dao.DeviceDAO{}.ActivateDevice(deviceActivation.DeviceID, auth.DB)
	if err != nil {
		return err
	}

	return nil
}

//RecoverAccount - activates a device
func (auth Authorize) RecoverAccount(recoveryRequest *types.RecoveryRequest) error {
	account, err := dao.AccountDAO{}.GetAccountByEmail(recoveryRequest.Email, auth.DB)
	if err != nil {
		return err
	}

	if account == nil {
		return errors.New("Account not found: " + recoveryRequest.Email)
	}

	recovery, err := dao.RecoverDAO{}.CreateRecovery(account, auth.DB)
	if err != nil {
		return err
	}

	//Send recovery email
	err = auth.Emailer.RecoverAccount(recovery)
	if err != nil {
		return errors.New("Recovery Email failed sending : " + err.Error())
	}

	return nil
}

//GetRecovery - returns a recovery
func (auth Authorize) GetRecovery(recovery *types.Recovery) (*types.Recovery, error) {
	rec, err := dao.RecoverDAO{}.GetRecovery(recovery, auth.DB)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, errors.New("No recovery was found: " + recovery.ID)
	}
	return rec, nil
}

//FinishRecovery - completes a recovery request
func (auth Authorize) FinishRecovery(recovery *types.FinalRecoveryRequest) (string, error) {
	rec, err := dao.RecoverDAO{}.GetRecovery(&types.Recovery{ID: recovery.ID}, auth.DB)
	if err != nil {
		return "", err
	}

	if rec == nil {
		return "", errors.New("No recovery was found: " + recovery.ID)
	}

	account, err := dao.AccountDAO{}.GetAccountByID(rec.AccountID, auth.DB)
	if err != nil {
		return "", err
	}
	if account == nil {
		return "", errors.New("No account was found: " + rec.AccountID)
	}

	account.Password = recovery.Password

	//Validate that the password is correct
	if err := account.CheckPassword(); err != nil {
		return err.Error(), nil
	}

	//Hash the password
	hash, err := utils.HashPassword(account.Password)
	if err != nil {
		return "", err
	}

	//Set password to  account object
	account.Password = hash

	res, err := dao.RecoverDAO{}.FinishRecovery(account, recovery, rec, auth.DB)
	if err != nil {
		return "", err
	}

	return res, nil
}

//ChangeAccountPassword - update requesting account password
func (auth Authorize) ChangeAccountPassword(tokens *types.AuthTokens, passwordRequest *types.UpdateAccountPassword) (string, error) {
	accountClams, err := auth.CheckAccessToken(tokens)
	if err != nil {
		return "", err
	}

	//Get account from JWT claims
	account, err := dao.AccountDAO{}.GetAccountByID(accountClams.ID, auth.DB)
	if err != nil {
		return "", err
	}

	//Make sure old password matches
	if !utils.CheckPasswordHash(passwordRequest.OldPassword, account.Password) {
		return "Old Password is wrong", nil
	}

	res, err := dao.AccountDAO{}.ChangeAccountPassword(account, passwordRequest, auth.DB)
	if err != nil {
		return "", err
	}

	return res, nil
}
