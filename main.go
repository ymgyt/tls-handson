package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"log"
	"strconv"
)

func Keyencription() {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("generating random key: %v", err)
	}

	plainText := []byte("when in Go do as other gophers do")
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, &privKey.PublicKey, plainText)
	if err != nil {
		log.Fatalf("could not encrypt data: %v", err)
	}
	fmt.Println("cipher text:")
	fmt.Printf("%s\n", strconv.Quote(string(cipherText)))

	decyptedText, err := rsa.DecryptPKCS1v15(nil, privKey, cipherText)
	if err != nil {
		log.Fatalf("decrypting cipher text: %v", err)
	}
	fmt.Printf("%s\n", decyptedText)
}

func Signature() {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("generating random key: %v", err)
	}

	plainText := []byte("when in Go do as other gophers do")
	hash := sha256.Sum256(plainText)
	fmt.Printf("the hash of plain text:\n%#x\n", hash)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hash[:])
	if err != nil {
		log.Fatalf("error creating signature: %v", err)
	}

	verify := func(pub *rsa.PublicKey, msg, signature []byte) error {
		hash := sha256.Sum256(msg)
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], signature)
	}

	fmt.Println(verify(&privKey.PublicKey, plainText, []byte("bad signature")))
	fmt.Println(verify(&privKey.PublicKey, []byte("a differenc plain text"), signature))
	fmt.Println(verify(&privKey.PublicKey, plainText, signature))
}

func main() {
	// Keyencription()
	Signature()
}
