package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"flag"
	"log"
	"os"
)

func main() {
	log.SetOutput(os.Stderr)
	log.SetFlags(0)

	key := flag.String("key", "", "AES `key` to encrypt with")
	nonce64 := flag.String("nonce", "", "nonce")
	ciphertext64 := flag.String("ciphertext", "", "ciphertext to decrypt")
	ad := flag.String("ad", "", "additional data to associate")
	flag.Parse()

	c, err := aes.NewCipher([]byte(*key))
	if err != nil {
		log.Fatal(err)
	}

	aead, err := cipher.NewGCM(c)
	if err != nil {
		log.Fatal(err)
	}

	nonce, err := base64.StdEncoding.DecodeString(*nonce64)
	if err != nil {
		log.Fatal(err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(*ciphertext64)
	if err != nil {
		log.Fatal(err)
	}

	text, err := aead.Open(nil, nonce, ciphertext, []byte(*ad))
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("text:\n%s", text)
}
