package aes

import (
	"crypto/rand"
	"fmt"
	"io"
	"slices"
)

type AESKey struct {
	key       []byte
	roundKeys [][]byte
}

var (
	keyBitSizes = []int{128, 192, 256}
	keySizes    = []int{16, 24, 32}
)

func NewAESKey(key []byte) (*AESKey, error) {
	if !slices.Contains(keySizes, len(key)) {
		return nil, fmt.Errorf("invalid key size")
	}
	a := &AESKey{key: key}
	a.roundKeys = a.keyExpansion()
	return a, nil
}

func (a *AESKey) KeySize() int {
	return len(a.key)
}

func GenerateAESKey(bitsize int) (*AESKey, error) {
	if !slices.Contains(keyBitSizes, bitsize) {
		return nil, fmt.Errorf("invalid key size")
	}
	key := make([]byte, bitsize/8)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return NewAESKey(key)
}

func (a *AESKey) Dump(writer io.Writer) error {
	_, err := writer.Write(a.key)
	return err
}

func LoadAESKey(reader io.Reader) (*AESKey, error) {
	key, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	return NewAESKey(key)
}
