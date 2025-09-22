package main

import (
	"flag"
	"info-security/internal/rsa"
	"io"
	"os"
)

func main() {
	inputFile := flag.String("input", "", "input file for encryption.")
	outputFile := flag.String("output", "", "output file to save as encrypted")
	publicKeyFile := flag.String("key", "./config/rsa/rsa.pub", "file with public RSA key. default: ./config/rsa/rsa.pub")
	flag.Parse()

	if *inputFile == "" || *outputFile == "" {
		panic("input and output files must be set")
	}

	publicKeyF, err := os.Open(*publicKeyFile)
	if err != nil {
		panic(err)
	}
	defer publicKeyF.Close()

	publicKey, err := rsa.LoadPublicRSA(publicKeyF)
	if err != nil {
		panic(err)
	}
	inputF, err := os.Open(*inputFile)
	if err != nil {
		panic(err)
	}
	inputBytes, err := io.ReadAll(inputF)
	if err != nil {
		panic(err)
	}
	encrypted, err := publicKey.Encrypt(inputBytes)
	if err != nil {
		panic(err)
	}

	outF, err := os.Create(*outputFile)
	if err != nil {
		panic(err)
	}

	defer outF.Close()
	_, err = outF.Write(encrypted)
	if err != nil {
		panic(err)
	}
}
