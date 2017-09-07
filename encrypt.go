package main

import (
	"bufio"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"

	"golang.org/x/crypto/ssh"
)

func encrypt(r io.Reader, ghUser string) ([]byte, error) {
	pubkey, err := getPubKey(ghUser)
	if err != nil {
		return nil, err
	}

	switch k := pubkey.(type) {
	case ssh.CryptoPublicKey:
		return encryptPK(os.Stdin, k.CryptoPublicKey())
	default:
		return nil, fmt.Errorf("pubkey not suitable for crypto (expected ssh.CryptoPublicKey but found %T)", k)
	}
}

func getPubKey(ghUser string) (ssh.PublicKey, error) {
	resp, err := http.Get(fmt.Sprintf("https://github.com/%s.keys", ghUser))
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	// Read first pubkey
	reader := bufio.NewReader(resp.Body)
	buf, err := reader.ReadBytes('\n')
	if err != nil {
		return nil, err
	}

	pubkey, _, _, _, err := ssh.ParseAuthorizedKey(buf)
	return pubkey, err
}

func encryptPK(r io.Reader, pk crypto.PublicKey) ([]byte, error) {
	switch k := pk.(type) {
	case *rsa.PublicKey:
		return encryptRSA(r, k)
	default:
		return nil, fmt.Errorf("unsupported pubkey: %T %v", k, k)
	}
}

func encryptRSA(r io.Reader, pk *rsa.PublicKey) ([]byte, error) {
	plainbuf, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	cipherbuf, err := rsa.EncryptPKCS1v15(rand.Reader, pk, plainbuf)
	if err != nil {
		return nil, err
	}

	return cipherbuf, nil
}
