package dao

import (
	"db"
	"errors"
	"strconv"
	"time"
	"types"
	"utils"

	"github.com/google/uuid"
	"github.com/kisielk/sqlstruct"
)

//AccountDAO - data access for accounts
type AccountDAO struct {
}

//CheckDuplicates - checks if account info already exists.
//Returns empty string and no error if no duplicates are found
//Returns string with an error message if duplicates are found
func (dao AccountDAO) CheckDuplicates(ID string, email string, db *db.MySQL) (string, error) {
	stmt, err := db.PreparedQuery("SELECT * FROM users WHERE email = ? AND id <> ?")
	if err != nil {
		return "", err
	}
	rows, err := stmt.Query(email, ID)
	if err != nil {
		return "", err
	}
	stmt.Close()
	defer rows.Close()
	for rows.Next() {
		return "Email is taken: " + email, nil
	}

	return "", nil
}

//CreateAccount - verifies and creates a new account
func (dao AccountDAO) CreateAccount(account *types.Account, db *db.MySQL) (string, error) {

	if err := account.CheckName(); err != nil {
		return err.Error(), nil
	}
	if err := account.CheckPassword(); err != nil {
		return err.Error(), nil
	}
	if err := account.CheckEmail(); err != nil {
		return err.Error(), nil
	}
	if err := account.CheckPhone(); err != nil {
		return err.Error(), nil
	}
	//Check if account details already exist with another account
	isDuplicate, err := dao.CheckDuplicates(account.ID, account.Email, db)
	if err != nil {
		return "", err
	}
	if isDuplicate != "" {
		return isDuplicate, nil
	}

	//Setup account details
	account.ID = uuid.New().String()
	account.Created = time.Now()
	account.Role = 100 //default

	//Hash password
	account.Password, err = utils.HashPassword(account.Password)
	if err != nil {
		return "", err
	}

	//Insert into database
	stmt, err := db.PreparedQuery("INSERT INTO users (id, password, role, firstName, lastName, phone, email, created) VALUES(?,?,?,?,?,?,?,?)")
	if err != nil {
		return "", err
	}
	_, err = stmt.Query(account.ID, account.Password, account.Role, account.FirstName, account.LastName, account.Phone, account.Email, account.Created)
	if err != nil {
		return "", err
	}
	stmt.Close()

	return "", nil
}

//DeleteAccount - deletes account from DB
func (dao AccountDAO) DeleteAccount(account *types.Account, db *db.MySQL) error {

	stmt, err := db.PreparedQuery("DELETE FROM users WHERE id = ?")
	if err != nil {
		return err
	}
	_, err = stmt.Query(account.ID)
	if err != nil {
		return err
	}

	stmt.Close()
	return nil

}

//GetAccountByEmail - returns an account by email
func (dao AccountDAO) GetAccountByEmail(email string, db *db.MySQL) (*types.Account, error) {
	stmt, err := db.PreparedQuery("SELECT * FROM users WHERE email = ?")
	if err != nil {
		return nil, err
	}
	rows, err := stmt.Query(email)
	if err != nil {
		return nil, err
	}
	stmt.Close()
	defer rows.Close()
	for rows.Next() {
		account := types.Account{}
		err = sqlstruct.Scan(&account, rows)
		if err != nil {
			return nil, err
		}
		return &account, nil
	}
	return nil, nil
}

//GetAccountByID - returns an account by ID
func (dao AccountDAO) GetAccountByID(id string, db *db.MySQL) (*types.Account, error) {
	stmt, err := db.PreparedQuery("SELECT * FROM users WHERE id = ?")
	if err != nil {
		return nil, err
	}
	rows, err := stmt.Query(id)
	if err != nil {
		return nil, err
	}
	stmt.Close()
	defer rows.Close()
	for rows.Next() {
		account := types.Account{}
		err = sqlstruct.Scan(&account, rows)
		if err != nil {
			return nil, err
		}
		return &account, nil
	}
	return nil, nil
}

//GetAccounts - returns all accounts with the role given
func (dao AccountDAO) GetAccounts(roles []int, db *db.MySQL) (*[]types.Account, error) {

	if len(roles) <= 0 {
		return nil, errors.New("Roles array is empty")
	}

	query := "SELECT * FROM users WHERE role = '" + strconv.Itoa(roles[0]) + "'"

	for i, r := range roles {
		if i == 0 {
			continue
		}
		query += " OR role = '" + strconv.Itoa(r) + "'"
	}

	//If the first role is 0, then we get all accounts
	if roles[0] == 0 {
		query = "SELECT * FROM users"
	}

	rows, err := db.SimpleQuery(query + " ORDER BY firstName ASC")
	if err != nil {
		return nil, err
	}
	accounts := []types.Account{}
	defer rows.Close()
	for rows.Next() {
		account := types.Account{}
		err := sqlstruct.Scan(&account, rows)
		if err != nil {
			//fmt.Println(err) -> fails to convert NULL to datatype
		}
		account.HideImportant()
		account.GetAccountPermissions()
		accounts = append(accounts, account)
	}
	return &accounts, nil
}

//UpdateSettings - updates the requesting accounts settings
func (dao AccountDAO) UpdateSettings(updatedAccount *types.Account, id string, db *db.MySQL) (string, error) {

	if err := updatedAccount.CheckName(); err != nil {
		return err.Error(), nil
	}
	if err := updatedAccount.CheckPhone(); err != nil {
		return err.Error(), nil
	}

	stmt, err := db.PreparedQuery("UPDATE users SET firstName = ?, lastName = ?, phone = ? WHERE id = ?")
	if err != nil {
		return "", err
	}
	_, err = stmt.Query(updatedAccount.FirstName, updatedAccount.LastName, updatedAccount.Phone, id)
	if err != nil {
		return "", err
	}
	stmt.Close()

	return "", nil
}

//UpdateAccount - updates the another users account settings
func (dao AccountDAO) UpdateAccount(updatedAccount *types.Account, db *db.MySQL) (string, error) {

	if err := updatedAccount.CheckPhone(); err != nil {
		return err.Error(), nil
	}
	if err := updatedAccount.CheckEmail(); err != nil {
		return err.Error(), nil
	}

	//Check if account details already exist with another account
	isDuplicate, err := dao.CheckDuplicates(updatedAccount.ID, updatedAccount.Email, db)
	if err != nil {
		return "", err
	}
	if isDuplicate != "" {
		return isDuplicate, nil
	}

	stmt, err := db.PreparedQuery("UPDATE users SET firstName = ?, lastName = ?, email = ?, phone = ?, role = ? WHERE id = ?")
	if err != nil {
		return "", err
	}
	_, err = stmt.Query(updatedAccount.FirstName, updatedAccount.LastName, updatedAccount.Email, updatedAccount.Phone, updatedAccount.Role, updatedAccount.ID)
	if err != nil {
		return "", err
	}
	stmt.Close()

	return "", nil
}

//ChangeAccountPassword - updates the requesting accounts password
func (dao AccountDAO) ChangeAccountPassword(account *types.Account, passwordRequest *types.UpdateAccountPassword, db *db.MySQL) (string, error) {

	//Set the new password
	account.Password = passwordRequest.NewPassword

	//Check the password
	if err := account.CheckPassword(); err != nil {
		return err.Error(), nil
	}

	//Hash password
	hash, err := utils.HashPassword(account.Password)
	if err != nil {
		return "", err
	}

	account.Password = hash

	stmt, err := db.PreparedQuery("UPDATE users SET password = ? WHERE id = ?")
	if err != nil {
		return "", err
	}
	_, err = stmt.Query(account.Password, account.ID)
	if err != nil {
		return "", err
	}
	stmt.Close()

	return "", nil
}
