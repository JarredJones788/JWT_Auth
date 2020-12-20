package db

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"io/ioutil"
	"log"
	"os"
	"time"
	"utils"

	"github.com/go-sql-driver/mysql"
	_ "github.com/go-sql-driver/mysql" //Mysql driver
)

//MySQL - MYSQL database class
type MySQL struct {
	SQL                  *sql.DB
	RefreshTokenDuration string
}

//Init - Start pooling with mysql
func (db MySQL) Init() (*MySQL, error) {

	//If an SSL key is provided use SSL.
	if os.Getenv("MYSQL_SSLKEY") != "" {
		//Get public key from file system
		pub, err := ioutil.ReadFile(os.Getenv("MYSQL_SSLKEY"))
		if err != nil {
			log.Fatal(err)
		}

		rootCertPool := x509.NewCertPool()

		if ok := rootCertPool.AppendCertsFromPEM(pub); !ok {
			log.Fatal("Failed adding MYSQL public key")
		}

		mysql.RegisterTLSConfig("custom", &tls.Config{
			RootCAs: rootCertPool,
		})

		pool, _ := sql.Open("mysql", os.Getenv("MYSQL_USER")+":"+os.Getenv("MYSQL_PASSWORD")+"@tcp("+os.Getenv("MYSQL_HOST")+":"+os.Getenv("MYSQL_PORT")+")/"+os.Getenv("MYSQL_DATABASE")+"?parseTime=true&tls=custom")
		if pool.Ping() != nil {
			return nil, errors.New("Cannot connect to database using SSL")
		}

		db.SQL = pool

	} else { //No SSL key was provided. Connect without.
		pool, _ := sql.Open("mysql", os.Getenv("MYSQL_USER")+":"+os.Getenv("MYSQL_PASSWORD")+"@tcp(["+os.Getenv("MYSQL_HOST")+"])/"+os.Getenv("MYSQL_DATABASE")+"?parseTime=true")
		if pool.Ping() != nil {
			return nil, errors.New("Cannot connect to database")
		}

		db.SQL = pool
	}

	db.RefreshTokenDuration = os.Getenv("TOKENS_REFRESH_TOKEN_DURATION")

	//Setup interval to remove expired data
	utils.Schedule(db.DeleteExpired, 1*time.Hour)

	return &db, nil
}

//PreparedQuery - returns a prepared statement
func (db MySQL) PreparedQuery(query string) (*sql.Stmt, error) {
	stmt, err := db.SQL.Prepare(query)
	if err != nil {
		return nil, err
	}
	return stmt, nil
}

//SimpleQuery - returns the result of a query
func (db MySQL) SimpleQuery(query string) (*sql.Rows, error) {
	q, err := db.SQL.Query(query)
	if err != nil {
		return nil, err
	}
	return q, nil
}

//DeleteExpired - removes all expired recoveries or devices
func (db MySQL) DeleteExpired() {

	rows1, _ := db.SimpleQuery("DELETE FROM recover WHERE created < (NOW() - INTERVAL 1 HOUR)")
	//rows2, _ := db.SimpleQuery("DELETE FROM emailChange WHERE created < (NOW() - INTERVAL 1 HOUR)")
	rows3, _ := db.SimpleQuery("DELETE FROM devices WHERE created < (NOW() - INTERVAL 60 DAY)")
	rows4, _ := db.SimpleQuery("DELETE FROM refreshtokens WHERE created < (NOW() - INTERVAL " + db.RefreshTokenDuration + " DAY)")

	rows1.Close()
	rows3.Close()
	rows4.Close()
}
