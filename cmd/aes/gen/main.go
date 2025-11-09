package main

import (
	"flag"
	"fmt"
	"info-security/internal/aes"
	"os"
	"slices"
)

func main() {
	bitsize := flag.Int("bitsize", 128, "key size in bits. Supported sizes: 128, 192, 256")
	output := flag.String("out", "./config/aes/key", "output file. Default: ./config/aes/key")
	flag.Parse()

	if !slices.Contains([]int{128, 192, 256}, *bitsize) {
		flag.Usage()
		return
	}
	fmt.Printf("key size: %d\n", *bitsize)

	aesKey, err := aes.GenerateAESKey(*bitsize)
	if err != nil {
		panic(err)
	}

	outFile, err := os.Create(*output)
	if err != nil {
		panic(err)
	}
	defer outFile.Close()

	err = aesKey.Dump(outFile)
	if err != nil {
		panic(err)
	}
}
