package main

import (
	"fmt"
	"info-security/internal/enigma"
)

const EnigmaConfigDir = "./config/enigma"

func configFileName(name string) string {
	return fmt.Sprintf("%s/%s.txt", EnigmaConfigDir, name)
}

func createRotor(name string) {
	rotor := enigma.RandomEnigmaRotor()
	err := enigma.DumpEnigmaRotor(rotor, configFileName(name))
	if err != nil {
		fmt.Println(err)
	}
}

func createReflector(name string) {
	reflector := enigma.RandomEnigmaReflector()
	err := enigma.DumpEnigmaReflector(reflector, configFileName(name))
	if err != nil {
		fmt.Println(err)
	}
}
func main() {
	createRotor("rotor1")
	createRotor("rotor2")
	createRotor("rotor3")
	createReflector("reflector1")
}
