package main

import (
	"flag"
	"info-security/internal/aes"
	"os"
	"slices"
)

func main() {
	inputFileName := flag.String("in", "", "input file name")
	outputFileName := flag.String("out", "", "output file name")
	keyFileName := flag.String("key", "./config/aes/key", "key file name. default: ./config/aes/key")
	opType := flag.String("op", "encrypt", "operation type. default: encrypt. possible values: encrypt, decrypt")
	flag.Parse()
	if *inputFileName == "" || *outputFileName == "" || *keyFileName == "" || !slices.Contains([]string{"encrypt", "decrypt"}, *opType) {
		flag.Usage()
		return
	}

	keyFile, err := os.Open(*keyFileName)
	if err != nil {
		panic(err)
	}
	defer keyFile.Close()

	key, err := aes.LoadAESKey(keyFile)
	if err != nil {
		panic(err)
	}

	inputFile, err := os.Open(*inputFileName)
	if err != nil {
		panic(err)
	}
	defer inputFile.Close()

	outputFile, err := os.Create(*outputFileName)
	if err != nil {
		panic(err)
	}
	defer outputFile.Close()

	switch *opType {
	case "encrypt":
		err = key.Encrypt(inputFile, outputFile)
	case "decrypt":
		err = key.Decrypt(inputFile, outputFile)
	}
	if err != nil {
		panic(err)
	}

}
