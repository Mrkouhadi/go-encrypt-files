package main

import (
	"fmt"
	"os"

	"github.com/mrkouhadi/go-encrypt-files/filecrypt"
)

// running command: go run . encrypt ./static/file.txt
func main() {
	fmt.Println("######################## EBCRYPTING AND DECRYPTING of FILES! ########################")
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(0)
	}
	function := os.Args[1]

	switch function {
	case "help":
		printHelp()
	case "encrypt":
		filecrypt.EncryptionHanlder()
	case "decrypt":
		filecrypt.DecryptionHanlder()
	default:
		fmt.Println("Run encrytion/decryption of a file")
		os.Exit(1)
	}
}
func printHelp() {
	fmt.Println("Usage:")
	fmt.Println("")
	fmt.Println("\t go run . encrypt /path/to/your/file")
	fmt.Println("")
	fmt.Println("Commands:")
	fmt.Println("")
	fmt.Println("\t encrypt\tEncrypts a file given a password")
	fmt.Println("\t decrypt\tTries to decrypt a file using a password")
	fmt.Println("\t help \t\t Displays help text")
	fmt.Println("")
}
