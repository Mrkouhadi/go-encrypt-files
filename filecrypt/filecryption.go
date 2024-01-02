package filecrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"io"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

func Encrypt(source string, password []byte) {
	if _, err := os.Stat(source); os.IsNotExist(err) {
		panic(err.Error())
	}
	srcFile, err := os.Open(source)
	if err != nil {
		panic(err.Error())
	}
	defer srcFile.Close()
	plainText, err := io.ReadAll(srcFile)
	if err != nil {
		panic(err.Error())
	}
	key := password
	noce := make([]byte, 12) // [0,0,0,0,0,....]
	if _, err := io.ReadFull(rand.Reader, noce); err != nil {
		panic(err.Error())
	}
	dk := pbkdf2.Key(key, noce, 4096, 32, sha1.New)
	block, err := aes.NewCipher(dk)
	if err != nil {
		panic(err.Error())
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	cipherTxt := aesgcm.Seal(nil, noce, plainText, nil)
	cipherTxt = append(cipherTxt, noce...)
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
