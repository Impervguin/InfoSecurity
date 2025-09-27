package des

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"info-security/internal/utils/perm"
	"io"
)

type DESKey struct {
	Key uint64
}

func NewDESKey(key uint64) *DESKey {
	return &DESKey{
		Key: key,
	}
}

func RandomDESKey() *DESKey {
	keyBytes := make([]byte, 8)
	_, err := rand.Read(keyBytes)
	if err != nil {
		panic(err)
	}
	for i := 0; i < 8; i++ {
		keyBytes[i] = setParity(keyBytes[i])
	}
	return NewDESKey(binary.BigEndian.Uint64(keyBytes))
}

func setParity(b byte) byte {
	ones := 0
	for i := 0; i < 7; i++ {
		if (b & (1 << i)) != 0 {
			ones++
		}
	}
	// set parity bit so that the number of 1s is odd
	if ones%2 == 0 {
		b |= 0x80
	} else {
		b &^= 0x80
	}
	return b
}

type DESSubKeys struct {
	Keys [16]uint64
}

func NewDESSubKeys(keys [16]uint64) *DESSubKeys {
	return &DESSubKeys{
		Keys: keys,
	}
}

var leftPermutation = []uint8{
	57, 49, 41, 33, 25, 17, 9, 1,
	58, 50, 42, 34, 26, 18, 10, 2,
	59, 51, 43, 35, 27, 19, 11, 3,
	60, 52, 44, 36,
}

var rightPermutation = []uint8{
	63, 55, 47, 39, 31, 23, 15, 7,
	62, 54, 46, 38, 30, 22, 14, 6,
	61, 53, 45, 37, 29, 21, 13, 5,
	28, 20, 12, 4,
}

var keyResultPermutation = []uint8{
	14, 17, 11, 24, 1, 5,
	3, 28, 15, 6, 21, 10,
	23, 19, 12, 4, 26, 8,
	16, 7, 27, 20, 13, 2,
	41, 52, 31, 37, 47, 55,
	30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53,
	46, 42, 50, 36, 29, 32,
}

var shifts = []uint8{1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1}

func (de *DESKey) GenerateSubKeys() *DESSubKeys {
	var subKeys [16]uint64

	var c, d uint64
	c = perm.PermuteBlock(de.Key, leftPermutation)
	d = perm.PermuteBlock(de.Key, rightPermutation)

	for i := 0; i < 16; i++ {
		c = perm.RotateLeftBase(c, int(shifts[i]), 28)
		d = perm.RotateLeftBase(d, int(shifts[i]), 28)
		res := (c << 28) | d
		subKeys[i] = perm.PermuteBlock(res, keyResultPermutation)
	}
	return NewDESSubKeys(subKeys)
}

func (de *DESKey) Dump(writer io.Writer) error {
	_, err := fmt.Fprintf(writer, "DES Key:\n")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(writer, "%d\n", de.Key)
	if err != nil {
		return err
	}

	return nil
}

func LoadDESKey(reader io.Reader) (*DESKey, error) {
	var key uint64
	_, err := fmt.Fscanf(reader, "DES Key:\n")
	if err != nil {
		return nil, err
	}
	_, err = fmt.Fscanf(reader, "%d\n", &key)
	if err != nil {
		return nil, err
	}

	return NewDESKey(key), nil
}
