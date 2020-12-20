package signer

import (
	"crypto/rsa"
	"io/ioutil"
	"os"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

//AccountInfo - struct of JWT access token
type AccountInfo struct {
	ID        string   `json:"id"`
	FirstName string   `json:"firstName"`
	LastName  string   `json:"lastName"`
	Email     string   `json:"email"`
	Roles     []string `json:"roles"`
}

//AccessClaims - struct of access claim
type AccessClaims struct {
	*jwt.StandardClaims
	*AccountInfo
}

//JWTSigner - struct  to sign jwt
type JWTSigner struct {
	signKey             *rsa.PrivateKey
	verifyKey           *rsa.PublicKey
	AccessTokenDuration time.Duration
}

//SignedResponse - successful response from signed JWT
type SignedResponse struct {
	AccessToken  string
	RefreshToken string
}

//Init - Inits JWTSigner
func (j *JWTSigner) Init() error {

	//Get private key from file system
	signBytes, err := ioutil.ReadFile(os.Getenv("TOKENS_PRIVATE_KEY"))
	if err != nil {
		return err
	}

	//Generate the signing key from private key
	j.signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		return err
	}

	//Get Public key from file system
	verifyBytes, err := ioutil.ReadFile(os.Getenv("TOKENS_PUBLIC_KEY"))
	if err != nil {
		return err
	}

	//Generates the verifying key from public key
	j.verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		return err
	}

	num, err := strconv.Atoi(os.Getenv("TOKENS_ACCESS_TOKEN_DURATION"))
	if err != nil {
		//Was an error set default
		j.AccessTokenDuration = time.Minute * 15
	} else {
		//Set duration from config
		j.AccessTokenDuration = time.Minute * time.Duration(num)
	}

	return nil
}

//SignNewJWT - Signs a new JWT with account info
func (j *JWTSigner) SignNewJWT(account *AccountInfo) (*SignedResponse, error) {

	//Get access token
	access, err := j.CreateAccessToken(account)
	if err != nil {
		return nil, err
	}

	//Get refresh token
	refresh := j.createRefreshToken()

	return &SignedResponse{AccessToken: access, RefreshToken: refresh}, nil
}

//CreateAccessToken - create a new access token for the given account
func (j *JWTSigner) CreateAccessToken(account *AccountInfo) (string, error) {

	//Initiate tokens
	accessToken := jwt.New(jwt.GetSigningMethod("RS256"))

	//Create claims for access token
	accessToken.Claims = &AccessClaims{
		&jwt.StandardClaims{
			ExpiresAt: time.Now().Add(j.AccessTokenDuration).Unix(),
		},
		account,
	}

	//Sign access token with signing key
	access, err := accessToken.SignedString(j.signKey)
	if err != nil {
		return "", err
	}

	return access, nil
}

//createRefreshToken - create a new refresh token
func (j *JWTSigner) createRefreshToken() string {
	return uuid.New().String()
}

//RefreshJWT - Verify refresh and access token are valid and match. Then provide new access token.
func (j *JWTSigner) RefreshJWT(refreshToken string) string {

	return ""
}

//VerifyAccessToken - Verify access token is valid
func (j *JWTSigner) VerifyAccessToken(token string) (*AccessClaims, error) {

	res, err := jwt.ParseWithClaims(token, &AccessClaims{}, func(token *jwt.Token) (interface{}, error) {
		return j.verifyKey, nil
	})

	if err != nil {
		return nil, err
	}

	return res.Claims.(*AccessClaims), nil
}

//ParseAccessToken_UNSAFE - UNSAFE DONT USE UNLESS YOU HAVE ALREADY VERIFIED ACCESS TOKEN WITH VerifyAccessToken
func (j *JWTSigner) ParseAccessToken_UNSAFE(token string) (*AccessClaims, error) {

	t := &jwt.Parser{}

	res, _, err := t.ParseUnverified(token, &AccessClaims{})

	if err != nil {
		return nil, err
	}

	return res.Claims.(*AccessClaims), nil
}
