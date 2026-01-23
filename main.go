package main

import (
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v4"
)

const TOKEN_FILE = "token"

func main() {
	token, err := os.ReadFile(TOKEN_FILE)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Token: %s\n", token)

	parsedToken, err := jwt.Parse(string(token), nil)
	if err != nil {
		fmt.Printf("Error parsing token: %s\n", err)
	}

	if parsedToken == nil {
		fmt.Println("Parsed token is nil")
		return
	}

	// Print the expiration time of the token
	if exp, ok := parsedToken.Claims.(jwt.MapClaims)["exp"]; ok {
		fmt.Printf("Token expiration time: %v\n", exp)
	} else {
		fmt.Println("Expiration time not found in token claims")
	}
}
