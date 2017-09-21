package main

import (
	"bufio"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
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

func encryptAll(r io.Reader) (*SecretishBox, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}

	box := &SecretishBox{}

	if err := encryptKey(key, box); err != nil {
		return nil, err
	}

	plainbuf, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	if err := encryptPlaintext(plainbuf, key, box); err != nil {
		return nil, err
	}

	return box, nil
}

func encryptKey(key []byte, box *SecretishBox) error {
	err := walkSSHDir(func(path string, info os.FileInfo, err error) error {
		if filepath.Ext(path) != ".pub" {
			return nil
		}

		raw, err := ioutil.ReadFile(path)
		if err != nil {
			log.Printf("error reading public key file %q: %v", path, err)
		}

		out, _, _, _, err := ssh.ParseAuthorizedKey(raw)
		if err != nil {
			log.Printf("error parsing public key file %q: %v", path, err)
		}

		switch k := out.(type) {
		case ssh.CryptoPublicKey:
			cipherkey, err := encryptPK(key, k.CryptoPublicKey())
			if err != nil {
				log.Printf("error encrypting key with pubkey %q: %v", path, err)
				return nil
			}
			box.Key = append(box.Key, &EncryptedKey{Ciphertext: cipherkey})
		default:
			log.Printf("pubkey not suitable for crypto (expected ssh.CryptoPublicKey but found %T)", k)
		}

		return nil
	})

	if err != nil {
		return err
	}

	if len(box.Key) == 0 {
		return fmt.Errorf("no suitable encryption keys found")
	}
	return nil
}

func encryptPlaintext(plaintext []byte, key []byte, box *SecretishBox) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	box.Nonce = make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, box.Nonce); err != nil {
		return err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	box.Ciphertext = aesgcm.Seal(nil, box.Nonce, plaintext, nil)
	return nil
}

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

	plainbuf, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	switch k := pubkey.(type) {
	case ssh.CryptoPublicKey:
		return encryptPK(plainbuf, k.CryptoPublicKey())
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

func encryptPK(buf []byte, pk crypto.PublicKey) ([]byte, error) {
	switch k := pk.(type) {
	case *rsa.PublicKey:
		return encryptRSA(buf, k)
	default:
		return nil, fmt.Errorf("unsupported pubkey: %T %v", k, k)
	}
}

func encryptRSA(plainbuf []byte, pk *rsa.PublicKey) ([]byte, error) {
	cipherbuf, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pk, plainbuf, oaepLabel)
	if err != nil {
		return nil, err
	}

	return cipherbuf, nil
}
