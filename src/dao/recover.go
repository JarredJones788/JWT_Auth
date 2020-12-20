package dao

import (
	"db"
	"time"
	"types"

	"github.com/google/uuid"
	"github.com/kisielk/sqlstruct"
)

//RecoverDAO - data access for recovery requests
type RecoverDAO struct {
}

//CreateRecovery - creates a new recovery
func (dao RecoverDAO) CreateRecovery(account *types.Account, db *db.MySQL) (*types.Recovery, error) {

	recovery := types.Recovery{ID: uuid.New().String(), AccountID: account.ID, Created: time.Now(), Email: account.Email}

	stmt, err := db.PreparedQuery("INSERT INTO recover (id, accountId, created, email) VALUES(?,?,?,?)")
	if err != nil {
		return nil, err
	}
	rows, err := stmt.Query(recovery.ID, recovery.AccountID, recovery.Created, recovery.Email)
	if err != nil {
		return nil, err
	}
	stmt.Close()
	defer rows.Close()
	return &recovery, nil

}

//GetRecovery - returns a recovery from db
func (dao RecoverDAO) GetRecovery(recovery *types.Recovery, db *db.MySQL) (*types.Recovery, error) {
	stmt, err := db.PreparedQuery("SELECT * FROM recover WHERE id = ?")
	if err != nil {
		return nil, err
	}
	rows, err := stmt.Query(recovery.ID)
	if err != nil {
		return nil, err
	}
	stmt.Close()
	defer rows.Close()
	for rows.Next() {
		rec := types.Recovery{}
		err = sqlstruct.Scan(&rec, rows)
		if err != nil {
			return nil, err
		}
		return &rec, nil
	}
	return nil, nil
}

//FinishRecovery - completes a account recovery process
func (dao RecoverDAO) FinishRecovery(account *types.Account, recoveryRequest *types.FinalRecoveryRequest, recovery *types.Recovery, db *db.MySQL) (string, error) {

	stmt, err := db.PreparedQuery("UPDATE users SET password = ? WHERE id = ?")
	if err != nil {
		return "", err
	}
	rows, err := stmt.Query(account.Password, account.ID)
	if err != nil {
		return "", err
	}
	stmt.Close()
	defer rows.Close()

	//If this fails it will expire within the HOUR. The request is already completed.
	_, _ = db.SimpleQuery("DELETE FROM recover WHERE id = '" + recovery.ID + "'")

	return "", nil
}
