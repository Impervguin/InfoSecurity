package enigma

import (
	"errors"
	"fmt"
	"info-security/internal/utils/bimap"
	"math/rand"
	"os"
	"strconv"
)

type EnigmaRotor struct {
	bmap      *bimap.BiMap[byte]
	next      EnigmaPart
	shift     byte
	shiftEdge byte
}

var RotorByteUnknownError error = errors.New("unknown byte")

var _ MiddleEnigmaPart = (*EnigmaRotor)(nil)

func NewEnigmaRotor(bmap *bimap.BiMap[byte], next EnigmaPart, shiftEdge byte) *EnigmaRotor {
	return &EnigmaRotor{
		bmap:      bmap,
		next:      next,
		shift:     0,
		shiftEdge: shiftEdge,
	}
}

func (r *EnigmaRotor) Apply(data byte) (byte, error) {
	data += r.shift
	d, ok := r.bmap.GetLeft(data)
	if !ok {
		return 0, RotorByteUnknownError
	}
	d2, err := r.next.Apply(d)
	if err != nil {
		return 0, err
	}
	d3, ok := r.bmap.GetRight(d2)
	if !ok {
		return 0, RotorByteUnknownError
	}
	return d3 - r.shift, nil
}

func (r *EnigmaRotor) After(part EnigmaPart) {
	r.next = part
}

func (r *EnigmaRotor) Update() {
	r.shift++
	if r.shift == r.shiftEdge {
		r.next.Update()
	}
}

func ReadEnigmaRotor(fName string) (*EnigmaRotor, error) {
	f, err := os.Open(fName)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var shiftEdge byte
	_, err = fmt.Fscanln(f, &shiftEdge)
	if err != nil {
		return nil, err
	}

	bmap, err := bimap.ReadBiMap[byte](f, func(s string) (byte, error) {
		b, err := strconv.ParseUint(s, 10, 8)
		if err != nil {
			return 0, err
		}
		return byte(b), nil
	})
	if err != nil {
		return nil, err
	}

	return NewEnigmaRotor(bmap, nil, shiftEdge), nil
}

func DumpEnigmaRotor(r *EnigmaRotor, fName string) error {
	f, err := os.OpenFile(fName, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%d\n", r.shiftEdge)
	if err != nil {
		return err
	}
	return bimap.DumpBiMap(r.bmap, f)
}

func RandomEnigmaRotor() *EnigmaRotor {
	barr := make([]byte, 256)
	for i := 0; i < 256; i++ {
		barr[i] = byte(i)
	}
	rand.Shuffle(256, func(i, j int) {
		barr[i], barr[j] = barr[j], barr[i]
	})
	bmap := bimap.NewBiMap[byte]()
	for i := 0; i < 256; i++ {
		bmap.Add(byte(i), barr[i])
	}
	shiftEdge := byte(rand.Intn(256))
	return NewEnigmaRotor(bmap, nil, shiftEdge)
}
