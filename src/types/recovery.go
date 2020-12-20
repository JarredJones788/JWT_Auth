package types

import "time"

//Recovery - struct for recovery class
type Recovery struct {
	ID        string    `sql:"id"`
	AccountID string    `sql:"accountId"`
	Email     string    `sql:"email"`
	Created   time.Time `sql:"created"`
}
