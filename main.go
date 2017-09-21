package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"os"
)

func main() {

	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(127)
	}

	op := flag.Arg(0)

	switch op {
	case "encrypt", "e":
		user := flag.Arg(1)
		if user != "" {
			ciphertext, err := encrypt(os.Stdin, user)
			if err != nil {
				log.Printf("error encrypting for user %q: %v", user, err)
				os.Exit(1)
			}

			out := base64.NewEncoder(base64.StdEncoding, os.Stdout)
			_, err = out.Write(ciphertext)
			out.Close()
			if err != nil {
				log.Printf("error encoding ciphertext: %v", err)
				os.Exit(1)
			}
		} else {

			box, err := encryptAll(os.Stdin)
			if err != nil {
				log.Printf("error encrypting: %v", err)
				os.Exit(1)
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(box); err != nil {
				log.Printf("error encoding box: %v", err)
				os.Exit(1)
			}
		}
	case "decrypt", "d":
		fn := flag.Arg(1)
		if fn == "" {
			log.Printf("missing filename to decrypt")
			os.Exit(1)
		}
		ciphertext, err := ioutil.ReadFile(fn)
		if err != nil {
			log.Printf("error reading %q: %v", fn, err)
			os.Exit(1)
		}

		var box SecretishBox
		var plaintext []byte
		if err := json.Unmarshal(ciphertext, &box); err == nil {
			// It's a json box!
			plaintext, err = decryptBox(&box)
			if err != nil {
				log.Printf("error decrypting box: %v", err)
				os.Exit(1)
			}
		} else {
			var in []byte
			if _, err := base64.StdEncoding.Decode(in, ciphertext); err != nil {
				log.Printf("error decoding ciphertext: %v", err)
				os.Exit(1)
			}
			plaintext, err = decryptBytes(in)
			if err != nil {
				log.Printf("error decrypting: %v", err)
				os.Exit(1)
			}
		}

		_, err = os.Stdout.Write(plaintext)
		if err != nil {
			log.Printf("error outputting plaintext: %v", err)
			os.Exit(1)
		}
	default:
		log.Printf("unknown operation: %q", op)
		flag.Usage()
		os.Exit(127)
	}

}
