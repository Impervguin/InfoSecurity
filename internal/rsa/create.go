package rsa

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

type RSA struct {
	Module          *big.Int
	PublicExponent  *big.Int
	PrivateExponent *big.Int
}

func NewRSA(bitSize int) (*RSA, error) {
	if (bitSize % 2) != 0 {
		return nil, fmt.Errorf("bitSize must be even")
	}

	p, err := rand.Prime(rand.Reader, bitSize/2)
	if err != nil {
		return nil, err
	}

	q, err := rand.Prime(rand.Reader, bitSize/2)
	if err != nil {
		return nil, err
	}

	for p.Cmp(q) == 0 {
		q, err = rand.Prime(rand.Reader, bitSize/2)
		if err != nil {
			return nil, err
		}
	}

	n := big.NewInt(0).Mul(p, q)
	phi := big.NewInt(0).Mul(big.NewInt(0).Sub(p, big.NewInt(1)), big.NewInt(0).Sub(q, big.NewInt(1)))

	e := big.NewInt(0).SetInt64(65537)

	// Check if e and phi are coprime
	gcd := big.NewInt(0).GCD(nil, nil, e, phi)
	if gcd.Cmp(big.NewInt(1)) != 0 {
		e := big.NewInt(17)
		gcd := big.NewInt(0).GCD(nil, nil, e, phi)
		for gcd.Cmp(big.NewInt(1)) != 0 {
			e = big.NewInt(0).Add(e, big.NewInt(2))
			gcd = big.NewInt(0).GCD(nil, nil, e, phi)
		}
	}

	d := big.NewInt(0).ModInverse(e, phi)
	return &RSA{
		Module:          n,
		PublicExponent:  e,
		PrivateExponent: d,
	}, nil
}

func (r *RSA) GetPublicKey() *RSAPublicKey {
	return NewRSAPublicKey(r.Module, r.PublicExponent)
}

func (r *RSA) GetPrivateKey() *RSAPrivateKey {
	return NewRSAPrivateKey(r.Module, r.PrivateExponent)
}
