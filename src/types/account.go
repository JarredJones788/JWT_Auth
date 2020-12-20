package types

import (
	"errors"
	"regexp"
	"time"
)

//Account - struct for account class
type Account struct {
	ID        string    `sql:"id" json:"-"`
	Password  string    `sql:"password" json:"password"`
	FirstName string    `sql:"firstName" json:"firstName"`
	LastName  string    `sql:"lastName" json:"lastName"`
	Phone     string    `sql:"phone" json:"phone"`
	Email     string    `sql:"email" json:"email"`
	Role      int       `sql:"role" json:"-"`
	TwoFA     bool      `sql:"twoFA" json:"twoFA"`
	Roles     []string  `json:"roles"`
	Created   time.Time `sql:"created" json:"-"`
	Disabled  bool      `sql:"disabled" json:"-"`
}

//CheckName - verify name is valid
func (account *Account) CheckName() error {
	if account.FirstName == "" {
		return errors.New("Invalid first name")
	}
	if account.LastName == "" {
		return errors.New("Invalid last name")
	}
	return nil
}

//CheckPassword - verify password is valid.
func (account *Account) CheckPassword() error {
	if len(account.Password) < 7 {
		return errors.New("Password must be 7 or more characters")
	}
	if !regexp.MustCompile(`\d`).MatchString(account.Password) {
		return errors.New("Password must contain a number")
	}
	if !regexp.MustCompile(`.*[a-zA-Z].*`).MatchString(account.Password) {
		return errors.New("Password must contain a letter")
	}
	return nil
}

//CheckEmail - verify email is valid.
func (account *Account) CheckEmail() error {
	if !regexp.MustCompile(`^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$`).MatchString(account.Email) {
		return errors.New("Invalid email address: " + account.Email)
	}
	return nil
}

//CheckPhone - verify phone is valid.
func (account *Account) CheckPhone() error {
	if !regexp.MustCompile(`^[\+]?[(]?[0-9]{3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,6}$`).MatchString(account.Phone) {
		return errors.New("Invalid phone number: " + account.Phone)
	}
	return nil
}

//HideImportant - Hides sensative info on the account
func (account *Account) HideImportant() {
	account.Password = ""
}

//GetAccountPermissions - gets the accounts permission.
func (account *Account) GetAccountPermissions() {
	account.Roles = GetRoles(account.Role)
}
