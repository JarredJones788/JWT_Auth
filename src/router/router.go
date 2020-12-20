package router

import (
	"auth"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
	"types"
	"utils"

	"github.com/gorilla/mux"
)

//Router type
type Router struct {
	Host         string
	Authenticate *auth.Authenticate
	Authorize    *auth.Authorize
}

//Init - inits all routes.
func (router Router) Init(authenticate *auth.Authenticate, authorize *auth.Authorize) error {

	router.Authenticate = authenticate
	router.Authorize = authorize
	router.Host = os.Getenv("HOST")

	//Setup mux router
	r := mux.NewRouter()
	router.setUpRoutes(r)
	fmt.Fprintln(os.Stderr, "Server Started")
	err := http.ListenAndServe(os.Getenv("PORT"), r)
	if err != nil {
		return err
	}

	return nil
}

//setUpRoutes - sets up all endpoints for the service
func (router Router) setUpRoutes(r *mux.Router) {
	r.HandleFunc("/api/auth/login", router.login)
	r.HandleFunc("/api/auth/logout", router.logout)
	r.HandleFunc("/api/auth/register", router.register)
	r.HandleFunc("/api/auth/delete", router.delete)
	r.HandleFunc("/api/auth/updatesettings", router.updateSettings)
	r.HandleFunc("/api/auth/updateaccount", router.updateAccount)
	r.HandleFunc("/api/auth/refresh", router.refreshToken)
	r.HandleFunc("/api/auth/getaccount", router.getAccount)
	r.HandleFunc("/api/auth/getaccounts", router.getAccounts)
	r.HandleFunc("/api/auth/activatedevice", router.activateDevice)
	r.HandleFunc("/api/auth/recoveraccount", router.recoverAccount)
	r.HandleFunc("/api/auth/getrecovery", router.getRecovery)
	r.HandleFunc("/api/auth/finishrecovery", router.finishRecovery)
	r.HandleFunc("/api/auth/changepassword", router.changeAccountPassword)
}

//-----------------HELPERS BELOW-----------------\\

//badRequest - returns a generic bad response
func (router Router) badRequest(w http.ResponseWriter) {
	failed, err := json.Marshal(types.GenericResponse{Response: false})
	if err != nil {
		w.Write([]byte("BACKEND ERROR"))
		return
	}
	w.Write(failed)
}

//goodRequest - returns a generic good response
func (router Router) goodRequest(w http.ResponseWriter) {
	w.WriteHeader(200)
	w.Write([]byte(""))
}

//reasonResponse - returns a response with a reason
func (router Router) reasonResponse(w http.ResponseWriter, response bool, reason string) {
	good, err := json.Marshal(types.ReasonResponse{Response: response, Reason: reason})
	if err != nil {
		w.Write([]byte("BACKEND ERROR"))
		return
	}
	w.Write(good)
}

//errorResponse - returns a error response
func (router Router) errorResponse(w http.ResponseWriter, httpStatusCode int, errorCode int, errorMsg string) {
	errorBody := types.ErrorResponseBody{HTTPStatusCode: httpStatusCode, ErrorCode: errorCode, ErrorMsg: errorMsg}
	res, err := json.Marshal(types.ErrorResponse{Error: errorBody})
	if err != nil {
		w.Write([]byte("BACKEND ERROR"))
		return
	}
	w.WriteHeader(httpStatusCode)
	w.Write(res)
}

//setUpHeaders - sets the desired headers for an http response
func (router Router) setUpHeaders(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Access-Control-Allow-Origin", router.Host)
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Max-Age", "120")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With")
	if r.Method == http.MethodOptions {
		w.WriteHeader(200)
		return false
	}
	return true
}

//getDeviceID - returns deviceId from request cookies
func (router Router) getDeviceID(r *http.Request) string {
	for _, cookie := range r.Cookies() {
		if cookie.Name == "deviceId" {
			return cookie.Value
		}
	}
	return ""
}

//getAccessToken - returns access token from authorization header
func (router Router) getAccessToken(r *http.Request) string {
	reqToken := r.Header.Get("Authorization")
	if reqToken == "" || !strings.Contains(reqToken, "Bearer") {
		return ""
	}
	splitToken := strings.Split(reqToken, "Bearer ")
	if len(splitToken) <= 1 || splitToken[1] == "null" {
		return ""
	}

	return splitToken[1]
}

//getRefreshToken - returns refresh token from request cookies
func (router Router) getRefreshToken(r *http.Request) string {
	for _, cookie := range r.Cookies() {
		if cookie.Name == "refreshToken" {
			return cookie.Value
		}
	}
	return ""
}

//addCookie - adds a cookie to a response
func (router Router) addCookie(w http.ResponseWriter, name string, value string) {
	expire := time.Now().AddDate(1, 0, 0)
	cookie := http.Cookie{
		Name:     name,
		Value:    value,
		HttpOnly: true,
		Expires:  expire,
		Path:     "/",
	}
	http.SetCookie(w, &cookie)
}

//-----------------ROUTES BELOW-----------------\\

//login - Endpoint to login. Requires email and password
func (router Router) login(w http.ResponseWriter, r *http.Request) {
	if !router.setUpHeaders(w, r) {
		return //request was an OPTIONS which was handled.
	}

	var loginDetails types.Login
	if err := json.NewDecoder(r.Body).Decode(&loginDetails); err != nil {
		fmt.Fprintln(os.Stderr, "Login Error: "+err.Error())
		router.errorResponse(w, 406, 5, "Invalid Request")
		return
	}

	//Get device id from cookie
	loginDetails.DeviceID = router.getDeviceID(r)

	//Get results from login attempt
	result, err := router.Authenticate.Login(&loginDetails)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Login Error: "+err.Error())
		router.errorResponse(w, 406, 5, "Invalid Request")
		return
	}

	//Device is not active, tell the client to activate it
	if !result.DeviceActive {
		responseInfo := &types.LoginResponseData{
			DeviceActive: result.DeviceActive,
		}

		//Create the json response
		data, err := json.Marshal(responseInfo)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Login Error: "+err.Error())
			router.errorResponse(w, 406, 5, "Invalid Request")
			return
		}

		//Save deviceid
		router.addCookie(w, "deviceId", result.DeviceID)

		w.WriteHeader(200)
		w.Write(data)
		return
	}

	//Make sure tokens exists
	if result.Tokens == nil {
		fmt.Fprintln(os.Stderr, "Login Error: Device is active but no tokens were provided")
		router.errorResponse(w, 406, 5, "Invalid Request")
		return
	}

	//Data that will be sent as a response
	responseInfo := &types.LoginResponseData{
		DeviceActive: result.DeviceActive,
		AccessToken:  result.Tokens.AccessToken,
	}

	//Create the json response
	data, err := json.Marshal(responseInfo)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Login Error: "+err.Error())
		router.errorResponse(w, 406, 5, "Invalid Request")
		return
	}

	//Save deviceid
	router.addCookie(w, "refreshToken", result.Tokens.RefreshToken)

	w.WriteHeader(200)
	w.Write(data)
}

//logout - endpoint to logout. removes and deletes refresh token.
func (router Router) logout(w http.ResponseWriter, r *http.Request) {
	if !router.setUpHeaders(w, r) {
		return //request was an OPTIONS which was handled.
	}

	tokens := &types.AuthTokens{
		RefreshToken: router.getRefreshToken(r),
	}

	err := router.Authenticate.Logout(tokens)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Logout Error: "+err.Error())
		router.errorResponse(w, 406, 5, "Invalid Request")
		return
	}

	//Remove Refresh token
	router.addCookie(w, "refreshToken", "")

	router.goodRequest(w)
}

//register - endpoint to register a new account
func (router Router) register(w http.ResponseWriter, r *http.Request) {

	if !router.setUpHeaders(w, r) {
		return //request was an OPTIONS which was handled.
	}

	var account types.Account
	if err := json.NewDecoder(r.Body).Decode(&account); err != nil {
		fmt.Fprintln(os.Stderr, "Register Error: "+err.Error())
		router.errorResponse(w, 406, 5, "Invalid Request")
		return
	}

	tokens := &types.AuthTokens{
		AccessToken: router.getAccessToken(r),
	}

	res, err := router.Authorize.RegisterAccount(tokens, &account)
	//Some error occured while trying to create the account
	if err != nil {
		fmt.Fprintln(os.Stderr, "Register Error: "+err.Error())
		router.errorResponse(w, 406, 5, "Invalid Request")
		return
	}

	//Return a bad response with the reason
	if res != "" {
		router.errorResponse(w, 406, 5, res)
		return
	}

	//Account created
	router.goodRequest(w)
}

//delete - endpoint to delete an account
func (router Router) delete(w http.ResponseWriter, r *http.Request) {

	if !router.setUpHeaders(w, r) {
		return //request was an OPTIONS which was handled.
	}
	var del types.DeleteAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&del); err != nil {
		fmt.Fprintln(os.Stderr, "Delete Error: "+err.Error())
		router.errorResponse(w, 406, 5, "Invalid Request")
		return
	}

	tokens := &types.AuthTokens{
		AccessToken: router.getAccessToken(r),
	}

	res, err := router.Authorize.DeleteAccount(tokens, &del)
	//Some error occured while trying to delete the account
	if err != nil {
		fmt.Fprintln(os.Stderr, "Delete Error: "+err.Error())
		router.errorResponse(w, 406, 5, "Invalid Request")
		return
	}

	//Return a bad response with the reason
	if res != "" {
		router.errorResponse(w, 406, 5, res)
		return
	}

	//Account deleted
	router.goodRequest(w)
}

//refreshToken - Endpoint to refresh an Access Token
func (router Router) refreshToken(w http.ResponseWriter, r *http.Request) {
	if !router.setUpHeaders(w, r) {
		return //request was an OPTIONS which was handled.
	}

	newToken, err := router.Authenticate.RefreshAccessToken(&types.AuthTokens{AccessToken: router.getAccessToken(r), RefreshToken: router.getRefreshToken(r)})
	if err != nil {
		fmt.Fprintln(os.Stderr, "RefreshToken Error: "+err.Error())
		router.errorResponse(w, 406, 5, "Invalid Request")
		return
	}

	//Data that will be sent as a response
	responseInfo := &types.AccessTokenResponse{
		AccessToken: newToken,
	}

	//Create the json response
	data, err := json.Marshal(responseInfo)
	if err != nil {
		fmt.Fprintln(os.Stderr, "RefreshToken Error: "+err.Error())
		router.errorResponse(w, 406, 5, "Invalid Request")
		return
	}

	w.WriteHeader(200)
	w.Write(data)
}

//getAccount - Endpoint to get account details of the requesting user.
func (router Router) getAccount(w http.ResponseWriter, r *http.Request) {
	if !router.setUpHeaders(w, r) {
		return //request was an OPTIONS which was handled.
	}

	account, err := router.Authorize.GetAccount(&types.AuthTokens{AccessToken: router.getAccessToken(r)})
	if err != nil {
		//Check if the error is a JWT related error
		if utils.IsExpired(err) {
			fmt.Fprintln(os.Stderr, "GetAccount Error: "+err.Error())
			router.errorResponse(w, 401, 10, "Access token is invalid")
			return
		}
		fmt.Fprintln(os.Stderr, "GetAccount Error: "+err.Error())
		router.errorResponse(w, 406, 5, "Invalid Request")
		return
	}

	//Create the json response
	data, err := json.Marshal(&account)
	if err != nil {
		fmt.Fprintln(os.Stderr, "GetAccount Error: "+err.Error())
		router.errorResponse(w, 406, 5, "Invalid Request")
		return
	}

	w.WriteHeader(200)
	w.Write(data)
}

//getAccounts - endpoint to get all accounts that match the roles provided. role 0 will get all accounts
func (router Router) getAccounts(w http.ResponseWriter, r *http.Request) {
	if !router.setUpHeaders(w, r) {
		return //request was an OPTIONS which was handled.
	}

	var request types.GetAccountsRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		fmt.Fprintln(os.Stderr, "GetAccounts Error: "+err.Error())
		router.errorResponse(w, 406, 5, "Invalid Request")
		return
	}

	tokens := &types.AuthTokens{
		AccessToken: router.getAccessToken(r),
	}

	accounts, err := router.Authorize.GetAccounts(tokens, request.Roles)
	if err != nil {
		fmt.Fprintln(os.Stderr, "GetAccounts Error: "+err.Error())
		router.errorResponse(w, 406, 5, "Invalid Request")
		return
	}

	data, err := json.Marshal(types.AllUsersResponse{Accounts: accounts})
	if err != nil {
		fmt.Fprintln(os.Stderr, "GetAccounts Error: "+err.Error())
		router.errorResponse(w, 406, 5, "Invalid Request")
		return
	}

	w.WriteHeader(200)
	w.Write(data)

}

//updateSettings - endpoint to update account settings
func (router Router) updateSettings(w http.ResponseWriter, r *http.Request) {
	if !router.setUpHeaders(w, r) {
		return //request was an OPTIONS which was handled.
	}
	var account types.Account
	if err := json.NewDecoder(r.Body).Decode(&account); err != nil {
		fmt.Fprintln(os.Stderr, "UpdateSettings Error: "+err.Error())
		router.errorResponse(w, 406, 5, "Invalid Request")
		return
	}

	tokens := &types.AuthTokens{
		AccessToken: router.getAccessToken(r),
	}

	res, err := router.Authorize.UpdateSettings(tokens, &account)
	//Some error occured while trying to create the account
	if err != nil {
		if utils.IsExpired(err) {
			fmt.Fprintln(os.Stderr, "Update Settings Error: "+err.Error())
			router.errorResponse(w, 401, 10, "Access token is invalid")
			return
		}
		fmt.Fprintln(os.Stderr, "UpdateSettings Error: "+err.Error())
		router.errorResponse(w, 406, 5, "Invalid Request")
		return
	}

	//Return a bad response with the reason
	if res != "" {
		router.errorResponse(w, 406, 5, res)
		return
	}

	//Account Updated
	router.goodRequest(w)
}

//updateAccount - endpoint to update another users account settings
func (router Router) updateAccount(w http.ResponseWriter, r *http.Request) {
	if !router.setUpHeaders(w, r) {
		return //request was an OPTIONS which was handled.
	}

	var account types.Account
	if err := json.NewDecoder(r.Body).Decode(&account); err != nil {
		fmt.Fprintln(os.Stderr, "UpdateAccount Error: "+err.Error())
		router.errorResponse(w, 406, 5, "Invalid Request")
		return
	}

	tokens := &types.AuthTokens{
		AccessToken: router.getAccessToken(r),
	}

	res, err := router.Authorize.UpdateAccount(tokens, &account)
	//Some error occured while trying to create the account
	if err != nil {
		fmt.Fprintln(os.Stderr, "UpdateAccount Error: "+err.Error())
		router.errorResponse(w, 406, 5, "Invalid Request")
		return
	}

	//Return a bad response with the reason
	if res != "" {
		router.errorResponse(w, 406, 5, res)
		return
	}

	//Account Updated
	router.goodRequest(w)
}

//activateDevice - endpoint to active a device.
func (router Router) activateDevice(w http.ResponseWriter, r *http.Request) {
	if !router.setUpHeaders(w, r) {
		return //request was an OPTIONS which was handled.
	}

	var deviceRequest types.ActivateDevice
	if err := json.NewDecoder(r.Body).Decode(&deviceRequest); err != nil {
		fmt.Fprintln(os.Stderr, "ActivateDevice Error: "+err.Error())
		router.errorResponse(w, 406, 5, "Invalid Request")
		return
	}

	//Check code is not empty.
	if deviceRequest.Code == "" {
		fmt.Fprintln(os.Stderr, "ActivateDevice Error: Empty Code")
		router.errorResponse(w, 406, 5, "Invalid Request")
	}

	//Get device id from cookie.
	deviceRequest.DeviceID = router.getDeviceID(r)

	//Check if activation is good
	err := router.Authorize.ActivateDevice(&deviceRequest)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ActivateDevice Error: "+err.Error())
		router.errorResponse(w, 406, 5, "Invalid Request")
		return
	}

	//Request was successful
	router.goodRequest(w)
}

//recoverAccount - endpoint to recover a account
func (router Router) recoverAccount(w http.ResponseWriter, r *http.Request) {
	if !router.setUpHeaders(w, r) {
		return //request was an OPTIONS which was handled.
	}

	var recoveryRequest types.RecoveryRequest
	if err := json.NewDecoder(r.Body).Decode(&recoveryRequest); err != nil {
		fmt.Fprintln(os.Stderr, "RecoverAccount Error: "+err.Error())
		router.errorResponse(w, 406, 5, "Invalid Request")
		return
	}

	err := router.Authorize.RecoverAccount(&recoveryRequest)
	if err != nil {
		fmt.Fprintln(os.Stderr, "RecoverAccount Error: "+err.Error())
		router.errorResponse(w, 406, 5, "Invalid Request")
		return
	}

	//Request was successful
	router.goodRequest(w)
}

//getRecover - endpoint to get an account recovery
func (router Router) getRecovery(w http.ResponseWriter, r *http.Request) {
	if !router.setUpHeaders(w, r) {
		return //request was an OPTIONS which was handled.
	}

	var recovery types.Recovery
	if err := json.NewDecoder(r.Body).Decode(&recovery); err != nil {
		fmt.Fprintln(os.Stderr, "GetRecovery Error: "+err.Error())
		router.errorResponse(w, 406, 5, "Invalid Request")
		return
	}

	_, err := router.Authorize.GetRecovery(&recovery)
	if err != nil {
		fmt.Fprintln(os.Stderr, "GetRecovery Error: "+err.Error())
		router.errorResponse(w, 406, 5, "Invalid Request")
		return
	}

	router.goodRequest(w)
}

//finishRecovery - endpoint to complete an account recovery
func (router Router) finishRecovery(w http.ResponseWriter, r *http.Request) {

	if !router.setUpHeaders(w, r) {
		return //request was an OPTIONS which was handled.
	}

	var recovery types.FinalRecoveryRequest
	if err := json.NewDecoder(r.Body).Decode(&recovery); err != nil {
		fmt.Fprintln(os.Stderr, "FinishRecovery Error: "+err.Error())
		router.errorResponse(w, 406, 5, "Invalid Request")
		return
	}

	//Attempt to finish recovery
	res, err := router.Authorize.FinishRecovery(&recovery)
	if err != nil {
		fmt.Fprintln(os.Stderr, "FinishRecovery Error: "+err.Error())
		router.errorResponse(w, 406, 5, "Invalid Request")
		return
	}

	//Return a bad response with the reason
	if res != "" {
		router.errorResponse(w, 406, 5, res)
		return
	}

	router.goodRequest(w)
}

//changeAccountPassword - endpoint to update requesting accounts password
func (router Router) changeAccountPassword(w http.ResponseWriter, r *http.Request) {
	if !router.setUpHeaders(w, r) {
		return //request was an OPTIONS which was handled.
	}
	var request types.UpdateAccountPassword
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		fmt.Fprintln(os.Stderr, "ChangePassword Error: "+err.Error())
		router.errorResponse(w, 406, 5, "Invalid Request")
		return
	}

	tokens := &types.AuthTokens{
		AccessToken: router.getAccessToken(r),
	}

	res, err := router.Authorize.ChangeAccountPassword(tokens, &request)
	//Some error occured while trying to create the account
	if err != nil {
		if utils.IsExpired(err) {
			fmt.Fprintln(os.Stderr, "ChangePassword Error: "+err.Error())
			router.errorResponse(w, 401, 10, "Access token is invalid")
			return
		}
		fmt.Fprintln(os.Stderr, "ChangePassword Error: "+err.Error())
		router.errorResponse(w, 406, 5, "Invalid Request")
		return
	}

	//Return a bad response with the reason
	if res != "" {
		router.errorResponse(w, 406, 5, res)
		return
	}

	//Password Updated
	router.goodRequest(w)
}
