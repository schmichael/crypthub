package main

import (
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
	"os"
	"strings"

	"github.com/hashicorp/vault/helper/password"
	"golang.org/x/crypto/ssh"
)

type Decrypter interface {
	Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error)
}

type RSAOAEPDecrypter struct {
	r *rsa.PrivateKey
}

func (r *RSAOAEPDecrypter) Decrypt(rand io.Reader, ciphertext []byte, _ crypto.DecrypterOpts) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand, r.r, ciphertext, oaepLabel)
}

func decryptBox(box *SecretishBox) ([]byte, error) {
	// try to decrypt each encrypted key with every private key
	// first get the private keys
	var decrypters []Decrypter
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
			decrypters = append(decrypters, &RSAOAEPDecrypter{k})
		case crypto.Decrypter:
			decrypters = append(decrypters, k)
		default:
			log.Printf("%q - key of type %T unsupported", path, k)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	// Try to decrypt each encrypted key with each decrypter until one works
	var key []byte

KeyLoop:
	for _, encryptedKey := range box.Key {
		for _, d := range decrypters {
			key, err = d.Decrypt(rand.Reader, encryptedKey.Ciphertext, nil)
			if err == nil {
				break KeyLoop
			}
		}
	}

	if len(key) == 0 {
		return nil, fmt.Errorf("unable to decrypt key with %d private keys", len(decrypters))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(box.Nonce) != aesgcm.NonceSize() {
		return nil, fmt.Errorf("expected nonce size %d but found %d (%q)", aesgcm.NonceSize(), len(box.Nonce), box.Nonce)
	}

	return aesgcm.Open(nil, box.Nonce, box.Ciphertext, nil)
}

func decryptBytes(ciphertext []byte) ([]byte, error) {
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
			plaintext, err = decryptRSA(ciphertext, k)
			if err != nil {
				log.Printf("rsa key %q failed with: %v", path, err)
				return nil
			}
			// It worked!
			return io.EOF
		case crypto.Decrypter:
			plaintext, err = decryptDecrypter(ciphertext, k)
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

func decryptRSA(ciphertext []byte, k *rsa.PrivateKey) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, k, ciphertext, oaepLabel)
}

func decryptDecrypter(ciphertext []byte, k crypto.Decrypter) ([]byte, error) {
	return k.Decrypt(rand.Reader, ciphertext, nil)
}
