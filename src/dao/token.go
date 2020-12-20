package dao

import (
	"db"
	"signer"
	"types"

	"github.com/kisielk/sqlstruct"
)

//TokenDAO - tokens data access object
type TokenDAO struct {
}

//SaveRefreshToken - saves a refresh token to the db
func (dao TokenDAO) SaveRefreshToken(account *types.Account, tokens *signer.SignedResponse, deviceID string, db *db.MySQL) (*types.RefreshToken, error) {
	token := types.RefreshToken{ID: tokens.RefreshToken, AccountID: account.ID, DeviceID: deviceID}

	stmt, err := db.PreparedQuery("INSERT INTO refreshtokens (id, accountId, deviceId) VALUES(?,?,?)")
	if err != nil {
		return nil, err
	}
	rows, err := stmt.Query(token.ID, token.AccountID, token.DeviceID)
	if err != nil {
		return nil, err
	}

	stmt.Close()
	defer rows.Close()

	return &token, nil
}

//GetRefreshToken - returns a refresh token
func (dao TokenDAO) GetRefreshToken(token string, db *db.MySQL) (*types.RefreshToken, error) {
	stmt, err := db.PreparedQuery("SELECT * FROM refreshtokens WHERE id = ?")
	if err != nil {
		return nil, err
	}
	rows, err := stmt.Query(token)
	if err != nil {
		return nil, err
	}
	stmt.Close()
	defer rows.Close()
	for rows.Next() {
		token := types.RefreshToken{}
		err = sqlstruct.Scan(&token, rows)
		if err != nil {
			return nil, err
		}
		return &token, nil
	}
	return nil, nil
}

//DeleteRefreshToken - deletes refresh token from DB
func (dao TokenDAO) DeleteRefreshToken(tokens *types.AuthTokens, db *db.MySQL) error {

	stmt, err := db.PreparedQuery("DELETE FROM refreshtokens WHERE id = ?")
	if err != nil {
		return err
	}
	_, err = stmt.Query(tokens.RefreshToken)
	if err != nil {
		return err
	}

	stmt.Close()
	return nil

}
