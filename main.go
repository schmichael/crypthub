package main

import (
	"encoding/base64"
	"flag"
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
	case "decrypt", "d":
		fn := flag.Arg(1)
		if fn == "" {
			log.Printf("missing filename to decrypt")
			os.Exit(1)
		}
		f, err := os.Open(fn)
		if err != nil {
			log.Printf("error opening %q: %v", fn, err)
			os.Exit(1)
		}
		in := base64.NewDecoder(base64.StdEncoding, f)
		plaintext, err := decrypt(in)
		if err != nil {
			log.Printf("error decrypting: %v", err)
			os.Exit(1)
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
