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
	privateKeyFile := flag.String("key", "./config/rsa/rsa.pri", "file with public RSA key. default: ./config/rsa/rsa.pri")
	flag.Parse()

	if *inputFile == "" || *outputFile == "" {
		panic("input and output files must be set")
	}

	priF, err := os.Open(*privateKeyFile)
	if err != nil {
		panic(err)
	}
	defer priF.Close()

	pri, err := rsa.Load(priF)
	if err != nil {
		panic(err)
	}

	inputF, err := os.Open(*inputFile)
	if err != nil {
		panic(err)
	}
	defer inputF.Close()
	inputBytes, err := io.ReadAll(inputF)
	if err != nil {
		panic(err)
	}
	decrypted, err := pri.Decrypt(inputBytes)
	if err != nil {
		panic(err)
	}
	outputF, err := os.Create(*outputFile)
	if err != nil {
		panic(err)
	}
	_, err = outputF.Write(decrypted)
	if err != nil {
		panic(err)
	}
}
