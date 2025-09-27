package main

import (
	"flag"
	"info-security/internal/des"
	"os"
	"slices"
)

func main() {
	inputFileName := flag.String("in", "", "input file name")
	outputFileName := flag.String("out", "", "output file name")
	keyFileName := flag.String("key", "./config/des/key.txt", "key file name. default: ./config/des/key.txt")
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

	key, err := des.LoadDESKey(keyFile)
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
