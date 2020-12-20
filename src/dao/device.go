package dao

import (
	"db"
	"time"
	"types"
	"utils"

	"github.com/google/uuid"
	"github.com/kisielk/sqlstruct"
)

//DeviceDAO - device data access object
type DeviceDAO struct {
}

//GetDevice - returns a device
func (dao DeviceDAO) GetDevice(deviceID string, db *db.MySQL) (*types.Device, error) {

	stmt, err := db.PreparedQuery("SELECT * FROM devices WHERE id = ?")
	if err != nil {
		return nil, err
	}
	rows, err := stmt.Query(deviceID)
	if err != nil {
		return nil, err
	}
	stmt.Close()
	defer rows.Close()
	for rows.Next() {
		device := types.Device{}
		err = sqlstruct.Scan(&device, rows)
		if err != nil {
			return nil, err
		}
		return &device, nil
	}
	return nil, nil
}

//CreateDevice - creates a new device
func (dao DeviceDAO) CreateDevice(account *types.Account, db *db.MySQL) (*types.Device, error) {
	device := types.Device{ID: uuid.New().String(), AccountID: account.ID, Created: time.Now(), Active: false, Code: utils.RandomCode()}

	stmt, err := db.PreparedQuery("INSERT INTO devices (id, accountId, created, active, code) VALUES(?,?,?,?,?)")
	if err != nil {
		return nil, err
	}
	rows, err := stmt.Query(device.ID, device.AccountID, device.Created, device.Active, device.Code)
	if err != nil {
		return nil, err
	}

	stmt.Close()
	defer rows.Close()

	return &device, nil
}

//ActivateDevice - activate the given device
func (dao DeviceDAO) ActivateDevice(deviceID string, db *db.MySQL) error {
	stmt, err := db.PreparedQuery("UPDATE devices SET active = 1 WHERE id = ?")
	if err != nil {
		return err
	}
	rows, err := stmt.Query(deviceID)
	if err != nil {
		return err
	}

	stmt.Close()
	defer rows.Close()

	return nil
}
