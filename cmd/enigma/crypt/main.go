package main

import (
	"bufio"
	"flag"
	"fmt"
	"info-security/internal/enigma"
	"io"
	"os"
)

const EnigmaConfigDir = "./config/enigma"

func configFileName(name string) string {
	return fmt.Sprintf("%s/%s.txt", EnigmaConfigDir, name)
}

func readReflector(name string) (*enigma.EnigmaReflector, error) {
	return enigma.ReadEnigmaReflector(configFileName(name))
}

func readRotor(name string) (*enigma.EnigmaRotor, error) {
	return enigma.ReadEnigmaRotor(configFileName(name))
}

type Args struct {
	inputFile  string
	outputFile string
}

func readArgs() *Args {
	args := &Args{}
	flag.StringVar(&args.inputFile, "input", "", "input file")
	flag.StringVar(&args.outputFile, "output", "", "output file")
	flag.Parse()
	if args.inputFile == "" {
		flag.Usage()
		return nil
	}
	if args.outputFile == "" {
		flag.Usage()
		return nil
	}
	return args
}

func main() {
	args := readArgs()
	if args == nil {
		return
	}
	reflector, err := readReflector("reflector1")
	if err != nil {
		panic(err)
	}
	rotor1, err := readRotor("rotor1")
	if err != nil {
		panic(err)
	}
	rotor2, err := readRotor("rotor2")
	if err != nil {
		panic(err)
	}
	rotor3, err := readRotor("rotor3")
	if err != nil {
		panic(err)
	}

	rotor1.After(rotor2)
	rotor2.After(rotor3)
	rotor3.After(reflector)

	machine := enigma.NewEnigmaMachine(rotor1)

	inFile, err := os.Open(args.inputFile)
	if err != nil {
		panic(err)
	}
	defer inFile.Close()

	outFile, err := os.Create(args.outputFile)
	if err != nil {
		panic(err)
	}
	defer outFile.Close()

	inBuf := bufio.NewReader(inFile)
	outBuf := bufio.NewWriter(outFile)
	defer outBuf.Flush()
	buf := make([]byte, 1024)
	endFile := false
	for !endFile {
		n, err := inBuf.Read(buf)

		if err != nil {
			if err == io.EOF && n == 0 {
				break
			} else if err == io.EOF {
				endFile = true
			}
			panic(err)
		}
		res, err := machine.Apply(buf[:n])
		if err != nil {
			panic(err)
		}
		outBuf.Write(res)
	}
}
