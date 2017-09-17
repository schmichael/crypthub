package main

import (
	"bufio"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

func encrypt(r io.Reader, keyid string) ([]byte, error) {
	var pubkey ssh.PublicKey

	err := walkSSHDir(func(path string, info os.FileInfo, err error) error {
		//TODO parse authorized_keys

		log.Printf("path: %q ext: %q", path, filepath.Ext(path))
		if filepath.Ext(path) != ".pub" {
			return nil
		}

		raw, err := ioutil.ReadFile(path)
		if err != nil {
			log.Printf("error reading public key file %q: %v", path, err)
		}

		out, comment, options, _, err := ssh.ParseAuthorizedKey(raw)
		if err != nil {
			log.Printf("error parsing public key file %q: %v", path, err)
		}

		if comment == keyid {
			log.Printf("Using %q (%q) from file %q", comment, options, path)
			pubkey = out
			return io.EOF
		}
		return nil
	})

	if pubkey == nil {
		pubkey, err = getPubKey(keyid)
		if err != nil {
			return nil, err
		}
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

	cipherbuf, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pk, plainbuf, oaepLabel)
	if err != nil {
		return nil, err
	}

	return cipherbuf, nil
}
