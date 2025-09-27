package main

import (
	"flag"
	"fmt"
	"info-security/internal/des"
	"os"
)

func main() {
	outFileName := flag.String("out", "./config/des/key.txt", "key file name. default: ./config/des/key.txt")
	flag.Parse()
	key := des.RandomDESKey()
	outFile, err := os.Create(*outFileName)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Key: %b\n", key.Key)
	defer outFile.Close()
	err = key.Dump(outFile)
	if err != nil {
		panic(err)
	}
}
