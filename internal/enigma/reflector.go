package enigma

import (
	"errors"
	"info-security/internal/utils/map_io"
	"math/rand"
	"strconv"
)

type EnigmaReflector struct {
	m map[byte]byte
}

var _ EnigmaPart = (*EnigmaReflector)(nil)

var ReflectorUnknownError error = errors.New("unknown byte")

func NewEnigmaReflector(m map[byte]byte) *EnigmaReflector {
	return &EnigmaReflector{
		m: m,
	}
}

func (r *EnigmaReflector) Apply(data byte) (byte, error) {
	if _, ok := r.m[data]; !ok {
		return 0, ReflectorUnknownError
	}
	return r.m[data], nil
}

func (r *EnigmaReflector) Update() {}

func ReadEnigmaReflector(fName string) (*EnigmaReflector, error) {
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
	return NewEnigmaReflector(m), nil
}

func DumpEnigmaReflector(r *EnigmaReflector, fName string) error {
	return map_io.DumpMap(r.m, fName)
}

func RandomEnigmaReflector() *EnigmaReflector {
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
	return NewEnigmaReflector(m)
}
