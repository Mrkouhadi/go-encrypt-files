package filecrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

func Encrypt(source string, password []byte) {
	if _, err := os.Stat(source); os.IsNotExist(err) {
		panic(err.Error())
	}
	// allow us to open the file
	err := os.Chmod(source, 0777)
	if err != nil {
		fmt.Println(err)
	}
	// read whts in the file
	plainText, err := os.ReadFile(source)
	if err != nil {
		panic(err.Error())
	}
	key := password
	nonce := make([]byte, 12) // [0,0,0,0,0,....]
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	dk := pbkdf2.Key(key, nonce, 4096, 32, sha1.New)
	block, err := aes.NewCipher(dk)
	if err != nil {
		panic(err.Error())
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	cipherTxt := aesgcm.Seal(nil, nonce, plainText, nil)
	cipherTxt = append(cipherTxt, nonce...)
	destinationFile, err := os.Create(source)
	if err != nil {
		panic(err.Error())
	}
	defer destinationFile.Close()
	_, err = destinationFile.Write(cipherTxt)
	if err != nil {
		panic(err.Error())
	}
}

func Decrypt(source string, password []byte) {
	if _, err := os.Stat(source); os.IsNotExist(err) {
		panic(err.Error())
	}
	srcFile, err := os.Open(source)
	if err != nil {
		panic(err.Error())
	}
	defer srcFile.Close()
	cipherTxt, err := io.ReadAll(srcFile)
	if err != nil {
		panic(err.Error())
	}
	key := password
	salt := cipherTxt[len(cipherTxt)-12:]
	str := hex.EncodeToString(salt)
	nonce, err := hex.DecodeString(str)
	dk := pbkdf2.Key(key, nonce, 4096, 32, sha1.New)
	block, err := aes.NewCipher((dk))
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := aesgcm.Open(nil, nonce, cipherTxt[:len(cipherTxt)-12], nil)
	if err != nil {
		panic(err.Error())
	}

	f, err := os.Create(source)
	if err != nil {
		panic(err.Error())
	}
	_, err = io.Copy(f, bytes.NewReader(plaintext))
	if err != nil {
		panic(err.Error())
	}
}
