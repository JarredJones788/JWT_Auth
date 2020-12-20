package auth

import (
	"dao"
	"db"
	"email"
	"errors"
	"signer"
	"types"
	"utils"

	"github.com/dgrijalva/jwt-go"
)

//Authenticate - Authenticate class
type Authenticate struct {
	DB      *db.MySQL
	Sign    *signer.JWTSigner
	Emailer *email.Emailer
}

//Init - Start authentication service
func (auth Authenticate) Init(jwt *signer.JWTSigner, db *db.MySQL, emailer *email.Emailer) *Authenticate {
	auth.DB = db
	auth.Sign = jwt
	auth.Emailer = emailer
	return &auth
}

//RefreshAccessToken - attempts to refresh an access token
func (auth Authenticate) RefreshAccessToken(tokens *types.AuthTokens) (string, error) {
	if tokens.RefreshToken == "" || tokens.AccessToken == "" {
		return "", errors.New("refresh token or access token is empty")
	}

	//Verify the current access token.
	_, err := auth.Sign.VerifyAccessToken(tokens.AccessToken)
	if err != nil {
		//Check if the access token is valid but has expired
		if e, ok := err.(*jwt.ValidationError); ok && e.Errors != jwt.ValidationErrorExpired {
			return "", errors.New("current access token is not valid")
		}
	}

	//Once we verify above that the access token is VALID
	//We want to get the account ID from the access token and verify it matches the one with the refresh token
	oldClaims, err := auth.Sign.ParseAccessToken_UNSAFE(tokens.AccessToken)
	if err != nil {
		return "", err
	}

	//Grab the refresh token provided by the user
	token, err := dao.TokenDAO{}.GetRefreshToken(tokens.RefreshToken, auth.DB)
	if err != nil {
		return "", err
	}

	//Token was not found
	if token == nil {
		return "", errors.New("no refresh token found")
	}

	//Verify access token account ID matches refresh token Account ID
	if oldClaims.ID != token.AccountID {
		return "", errors.New("Access token account id does not belong to the refresh token")
	}

	//Get the account attached to the refresh token
	account, err := dao.AccountDAO{}.GetAccountByID(token.AccountID, auth.DB)
	if err != nil {
		return "", err
	}

	//No account was found
	if account == nil {
		return "", errors.New("no account found from refresh token account id")
	}

	//Account has been disabled
	if account.Disabled {
		return "", errors.New("Account is disabled: " + account.Email)
	}

	//Fetch accounts permissions
	account.GetAccountPermissions()

	//If a device is attached to the refresh token or account has 2FA enabled then make sure it is still existing and active
	if token.DeviceID != "" || account.TwoFA {
		device, err := dao.DeviceDAO{}.GetDevice(token.DeviceID, auth.DB)
		if err != nil {
			return "", err
		}

		//Check if this device still exists
		if device == nil {
			return "", errors.New("device attached to refresh token is none existant, most likely expired")
		}

		//Make sure device is active
		if !device.Active {
			return "", errors.New("refresh device is not active")
		}

	}

	//Create account info for new Access Token
	accountInfo := &signer.AccountInfo{
		ID:        account.ID,
		FirstName: account.FirstName,
		LastName:  account.LastName,
		Email:     account.Email,
		Roles:     account.Roles,
	}

	//Generate the access token
	newToken, err := auth.Sign.CreateAccessToken(accountInfo)
	if err != nil {
		return "", err
	}

	return newToken, nil
}

//Login - Checks if login is valid
func (auth Authenticate) Login(login *types.Login) (*types.LoginResponse, error) {

	account, err := dao.AccountDAO{}.GetAccountByEmail(login.Email, auth.DB)
	if err != nil {
		return nil, err
	}

	//No email found
	if account == nil {
		return nil, errors.New("email not found: " + login.Email)
	}

	//Account has been disabled
	if account.Disabled {
		return nil, errors.New("Account is disabled: " + account.Email)
	}

	//Check if password matches hash
	valid := utils.CheckPasswordHash(login.Password, account.Password)
	if !valid {
		return nil, errors.New("Invalid Password Attempt: " + account.FirstName + " " + account.LastName)
	}

	//Get account roles
	account.GetAccountPermissions()

	accountInfo := &signer.AccountInfo{
		ID:        account.ID,
		FirstName: account.FirstName,
		LastName:  account.LastName,
		Email:     account.Email,
		Roles:     account.Roles,
	}

	//If account is ADMIN or above or 2FA is enabled then make sure device is verified.
	if utils.Contains("ADMIN", account.Roles) || account.TwoFA {

		dm := dao.DeviceDAO{}

		device, err := dm.GetDevice(login.DeviceID, auth.DB)
		if err != nil {
			return nil, err
		}

		//No device was found, need to create one.
		if err == nil && device == nil {
			device, err = dm.CreateDevice(account, auth.DB)
			if err != nil {
				return nil, err
			}
		}

		//If the device does not belong to the account.
		//Create a new one for the account.
		if account.ID != device.AccountID {
			device, err = dm.CreateDevice(account, auth.DB)
			if err != nil {
				return nil, err
			}
		}

		//If device is not setup, then only send device info
		if !device.Active {
			//Send new device email
			err := auth.Emailer.NewDeviceEmail(account, device)
			if err != nil {
				return nil, errors.New("New Device Email failed sending : " + err.Error())
			}

			return &types.LoginResponse{DeviceActive: device.Active, DeviceID: device.ID, Tokens: nil}, nil
		}

		//Device is setup, send device info and JWT tokens
		tokens, err := auth.Sign.SignNewJWT(accountInfo)
		if err != nil {
			return nil, err
		}

		//Save refresh token to DB
		_, err = dao.TokenDAO{}.SaveRefreshToken(account, tokens, device.ID, auth.DB)
		if err != nil {
			return nil, err
		}

		return &types.LoginResponse{DeviceActive: device.Active, DeviceID: device.ID, Tokens: tokens}, nil
	}

	tokens, err := auth.Sign.SignNewJWT(accountInfo)
	if err != nil {
		return nil, err
	}

	//Save refresh token to DB
	_, err = dao.TokenDAO{}.SaveRefreshToken(account, tokens, "", auth.DB)
	if err != nil {
		return nil, err
	}

	return &types.LoginResponse{DeviceActive: true, DeviceID: "", Tokens: tokens}, nil
}

//Logout - removes users session from system
func (auth Authenticate) Logout(tokens *types.AuthTokens) error {
	err := dao.TokenDAO{}.DeleteRefreshToken(tokens, auth.DB)
	if err != nil {
		return err
	}

	return nil
}
