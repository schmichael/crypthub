package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/hashicorp/vault/helper/password"
	"golang.org/x/crypto/ssh"
)

func decrypt(r io.Reader) ([]byte, error) {
	var plaintext []byte

	// try every file to see if its a key
	err := walkSSHDir(func(path string, info os.FileInfo, err error) error {
		buf, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}

		privkey, err := ssh.ParseRawPrivateKey(buf)
		if err != nil {
			if !strings.Contains(err.Error(), "cannot decode encrypted private keys") {
				log.Printf("error parsing private key %q: %v", path, err)
				return nil
			}

			// Prompt for password
			for {
				fmt.Fprintf(os.Stderr, "Enter password for key %q or press Ctrl-C to skip: ", path)
				pass, err := password.Read(os.Stdin)
				fmt.Println()
				if err == password.ErrInterrupted {
					return nil
				}
				if err != nil {
					return err
				}
				privkey, err = ssh.ParseRawPrivateKeyWithPassphrase(buf, []byte(pass))
				if err != nil {
					log.Printf("error parsing private key %q with password: %v", path, err)
					continue
				}
				break
			}
		}

		switch k := privkey.(type) {
		case *rsa.PrivateKey:
			plaintext, err = decryptRSA(r, k)
			if err != nil {
				log.Printf("rsa key %q failed with: %v", path, err)
				return nil
			}
			// It worked!
			return io.EOF
		case crypto.Decrypter:
			plaintext, err = decryptDecrypter(r, k)
			if err != nil {
				log.Printf("key %q failed with: %v", path, err)
				return nil
			}
			// It worked!
			return io.EOF
		default:
			log.Printf("key of type %T unsupported", k)
			return nil
		}
	})

	if plaintext != nil {
		return plaintext, nil
	}
	if err == nil {
		return nil, fmt.Errorf("no suitable decryption key found")
	}
	return nil, err
}

func decryptRSA(r io.Reader, k *rsa.PrivateKey) ([]byte, error) {
	buf, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	return rsa.DecryptOAEP(sha256.New(), rand.Reader, k, buf, oaepLabel)
}

func decryptDecrypter(r io.Reader, k crypto.Decrypter) ([]byte, error) {
	buf, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	return k.Decrypt(rand.Reader, buf, nil)
}
