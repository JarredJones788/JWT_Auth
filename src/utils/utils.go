package utils

import (
	"math/rand"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

//RandomString - returns a random string;
func RandomString() string {
	return uuid.New().String()
}

//RandomCode - returns a random 6 digit code
func RandomCode() string {
	var numbers = "0123456789"

	var seededRand *rand.Rand = rand.New(
		rand.NewSource(time.Now().UnixNano()))

	b := make([]byte, 6)
	for i := range b {
		b[i] = numbers[seededRand.Intn(len(numbers))]
	}
	return string(b)
}

//HashPassword - returns a has of the given password.
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	return string(bytes), err
}

//CheckPasswordHash - Checks if a password and hashed password are the same.
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

//Schedule - set an interval timer
func Schedule(what func(), delay time.Duration) chan bool {
	stop := make(chan bool)

	go func() {
		for {
			what()
			select {
			case <-time.After(delay):
			case <-stop:
				return
			}
		}
	}()

	return stop
}

//Contains - check if string is in array
func Contains(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

//IsExpired - checks if JWT had any validation issues.
func IsExpired(err error) bool {
	if _, ok := err.(*jwt.ValidationError); ok {
		return true
	}

	return false
}
