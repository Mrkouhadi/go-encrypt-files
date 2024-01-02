package filecrypt

import (
	"bytes"
	"fmt"
	"os"

	"golang.org/x/term"
)

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
	Encrypt(file, password)
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
	Decrypt(file, password)
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
