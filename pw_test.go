package pw

import (
	"fmt"
	"testing"
)

func TestPassword(t *testing.T) {
	password := "hello123"
	params, salt, hash, err := GenerateHash(password)
	if err != nil {
		panic(err)
	}
	fmt.Println(params, salt, hash)

	encodedHash := encodeHash(params, salt, hash)

	fmt.Println(encodedHash)
	decodedParams, decodedSalt, decodedHash, err := DecodeHash(encodedHash)
	if err != nil {
		panic(err)
	}
	fmt.Println(decodedParams, decodedSalt, decodedHash)

	isMatch, err := ComparePasswordAndHash(password, encodedHash)
	if err != nil {
		panic(err)
	}
	fmt.Printf("is match: %t\n", isMatch)
}

func TestPassword2(t *testing.T) {
	password := "lollol123"
	encodedHash, err := GenerateEncodedHash(password)
	if err != nil {
		panic(err)
	}
	fmt.Println(encodedHash)
	decodedParams, decodedSalt, decodedHash, err := DecodeHash(encodedHash)
	if err != nil {
		panic(err)
	}
	fmt.Println(decodedParams, decodedSalt, decodedHash)
	isMatch, err := ComparePasswordAndHash(password, encodedHash)
	if err != nil {
		panic(err)
	}
	fmt.Printf("is match: %t\n", isMatch)
}
