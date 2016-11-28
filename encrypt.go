package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"log"
	"os"
)

func main() {
	log.SetOutput(os.Stderr)
	log.SetFlags(0)

	key := flag.String("key", "", "AES `key` to encrypt with")
	text := flag.String("text", "", "some `text` to encrypt")
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

	nonce := make([]byte, aead.NonceSize())
	rand.Read(nonce)

	log.Printf("nonce:\n%s", base64.StdEncoding.EncodeToString(nonce))
	log.Printf("ciphertext:\n%s", base64.StdEncoding.EncodeToString(aead.Seal(nil, nonce, []byte(*text), []byte(*ad))))
}
