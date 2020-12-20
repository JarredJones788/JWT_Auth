package main

import (
	"auth"
	"db"
	"email"
	"fmt"
	"log"
	"router"
	"signer"

	"github.com/joho/godotenv"
)

func main() {

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	//Create JWT signer
	signer := &signer.JWTSigner{}
	if err := signer.Init(); err != nil {
		fmt.Println(err)
		return
	}

	//Connect to database
	db, err := db.MySQL{}.Init()
	if err != nil {
		fmt.Println(err)
		return
	}

	//Setup email instance
	emailer := email.Emailer{}.Init()

	//Create authentication class
	authentication := auth.Authenticate{}.Init(signer, db, emailer)

	//Create authorization class
	authorization := auth.Authorize{}.Init(signer, db, emailer)

	//Start router
	err = router.Router{}.Init(authentication, authorization)
	if err != nil {
		fmt.Println(err)
		return
	}
}
