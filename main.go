package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/mrkouhadi/go-encrypt-files/filecrypt"
	"golang.org/x/term"
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
		EncryptionHanlder()
	case "decrypt":
		DecryptionHanlder()
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

func EncryptionHanlder() {
	if len(os.Args) < 3 {
		fmt.Println("Missing the path to the file. for more info run . help")
		os.Exit(0)
	}
	file := os.Args[2]
	if !ValidateFile(file) {
		panic("File not found")
	}
	password := GetPassword()
	fmt.Println("\n Encrypting the file....")
	filecrypt.Encrypt(file, password)
	fmt.Println("\n File has been encrypted succesfully.")

}

func DecryptionHanlder() {
	if len(os.Args) < 3 {
		println("Missing the path to the file. For more information run CryptoGo help")
		os.Exit(0)
	}

	file := os.Args[2]

	if !ValidateFile(file) {
		panic("File not found")
	}

	fmt.Print("Enter password: ")
	password, _ := term.ReadPassword(0)

	fmt.Println("\nDecrypting...")
	filecrypt.Decrypt(file, password)
	fmt.Println("\nFile has been decrypted succesfully.")

}
func GetPassword() []byte {
	fmt.Println("Enter your password: ")
	password, _ := term.ReadPassword(0)
	fmt.Println("\n confirm your password:")
	password2, _ := term.ReadPassword(0)
	if !ValidatePassword(password, password2) {
		fmt.Println("\n Passwords do not mach. Try again")
	}
	return password
}

func ValidatePassword(p1, p2 []byte) bool {
	return bytes.Equal(p1, p2)
}
func ValidateFile(file string) bool {
	if _, err := os.Stat(file); os.IsNotExist(err) {
		return false
	}
	return true
}
