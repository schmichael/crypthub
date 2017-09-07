package main

import (
	"crypto"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func decrypt(r io.Reader) ([]byte, error) {
	sockPath := os.Getenv("SSH_AUTH_SOCK")
	if sockPath == "" {
		return nil, fmt.Errorf("$SSH_AUTH_SOCK not set")
	}

	sockFile, err := net.Dial("unix", sockPath)
	if err != nil {
		return nil, err
	}
	defer sockFile.Close()

	agentClient := agent.NewClient(sockFile)
	keys, err := agentClient.List()
	if err != nil {
		return nil, err
	}

	//FIXME lol can't get private keys from the agent and private keys are often encrypted on disk
	for _, k := range keys {
		fmt.Println(k.Format, k.Comment)
		_, err = ssh.ParseRawPrivateKey(k.Blob)
		if err != nil {
			// most files probably aren't keys, skip
			log.Printf("unable to parse: %v", err)
		}
	}
	/*
		// try every file to see if its a key
		err = filepath.Walk(sshdir, func(path string, info os.FileInfo, err error) error {
			if path == sshdir {
				return nil
			}
			if info.IsDir() {
				return filepath.SkipDir
			}

			if err != nil {
				return err
			}

			buf, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}


			switch k := privkey.(type) {
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
	*/
	return nil, err
}

func decryptDecrypter(r io.Reader, k crypto.Decrypter) ([]byte, error) {
	buf, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	return k.Decrypt(rand.Reader, buf, nil)
}
