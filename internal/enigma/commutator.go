package enigma

import (
	"info-security/internal/utils/map_io"
	"math/rand"
	"strconv"
)

type Commutator struct {
	next EnigmaPart
	m    map[byte]byte
}

var _ MiddleEnigmaPart = (*Commutator)(nil)

func NewCommutator(next EnigmaPart, m map[byte]byte) *Commutator {
	return &Commutator{
		next: next,
		m:    m,
	}
}

func (c *Commutator) Apply(data byte) (byte, error) {
	if _, ok := c.m[data]; !ok {
		return 0, nil
	}
	return c.m[data], nil
}

func (c *Commutator) Update() {
	c.next.Update()
}

func (c *Commutator) After(part EnigmaPart) {
	c.next = part
}

func ReadCommutator(fName string) (*Commutator, error) {
	m, err := map_io.ReadMap(fName, func(s string) (byte, error) {
		b, err := strconv.ParseUint(s, 10, 8)
		if err != nil {
			return 0, err
		}
		return byte(b), nil
	})
	if err != nil {
		return nil, err
	}
	return NewCommutator(nil, m), nil
}

func DumpCommutator(c *Commutator, fName string) error {
	return map_io.DumpMap(c.m, fName)
}

func RandomCommutator() *Commutator {
	arr := make([]byte, 128)
	for i := 0; i < 128; i++ {
		arr[i] = byte(i) + 128
	}
	rand.Shuffle(128, func(i, j int) {
		arr[i], arr[j] = arr[j], arr[i]
	})
	m := make(map[byte]byte, 128)
	for i := 0; i < 128; i++ {
		m[byte(i)] = arr[i]
		m[arr[i]] = byte(i)
	}
	return NewCommutator(nil, m)
}
