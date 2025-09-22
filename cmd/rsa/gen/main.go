package main

import (
	"flag"
	"info-security/internal/rsa"
	"os"
)

func main() {
	bitSize := flag.Int("b", 2048, "bit size of keys. default: 2048")
	priFile := flag.String("pri", "rsa.key", "private key file. default: rsa.key")
	pubFile := flag.String("pub", "rsa.pub", "public key file. default: rsa.pub")
	flag.Parse()

	key, err := rsa.NewRSA(*bitSize)
	if err != nil {
		panic(err)
	}
	pri := key.GetPrivateKey()
	pub := key.GetPublicKey()

	priF, err := os.OpenFile(*priFile, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}
	defer priF.Close()
	err = pri.Dump(priF)
	if err != nil {
		panic(err)
	}

	pubF, err := os.OpenFile(*pubFile, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}
	defer pubF.Close()
	err = pub.Dump(pubF)
	if err != nil {
		panic(err)
	}
}
