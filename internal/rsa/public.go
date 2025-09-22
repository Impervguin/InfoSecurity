package rsa

import (
	"fmt"
	"io"
	"math/big"
)

type RSAPublicKey struct {
	Module         *big.Int
	PublicExponent *big.Int
}

func NewRSAPublicKey(n *big.Int, e *big.Int) *RSAPublicKey {
	return &RSAPublicKey{
		Module:         n,
		PublicExponent: e,
	}
}

func (r *RSAPublicKey) Encrypt(message []byte) ([]byte, error) {
	blockSize := (r.Module.BitLen()) / 8
	if blockSize <= 0 {
		return nil, fmt.Errorf("blockSize must be greater than 0")
	}
	result := make([]byte, 0, len(message))
	for i := 0; i < len(message); i += blockSize {
		end := i + blockSize
		if end > len(message) {
			end = len(message)
		}
		block := message[i:end]

		num := big.NewInt(0).SetBytes(block)
		// if num.Cmp(r.Module) != -1 {
		// 	return nil, fmt.Errorf("block is bigger than modulus")
		// }
		encrypted := big.NewInt(0).Exp(num, r.PublicExponent, r.Module)
		encryptedBytes := encrypted.Bytes()
		if len(encryptedBytes) > blockSize {
			return nil, fmt.Errorf("encrypted block is bigger than blockSize")
		}
		if len(encryptedBytes) < blockSize {
			encryptedBytes = append(make([]byte, blockSize-len(encryptedBytes)), encryptedBytes...)
		}
		result = append(result, encryptedBytes...)
	}

	return result, nil
}

func (r *RSAPublicKey) Dump(reader io.Writer) error {
	_, err := fmt.Fprintf(reader, "Public Key:\n")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(reader, "%s\n", r.Module.String())
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(reader, "%s\n", r.PublicExponent.String())
	if err != nil {
		return err
	}

	return nil
}

func LoadPublicRSA(reader io.Reader) (*RSAPublicKey, error) {
	var moduleStr string
	var publicExponentStr string

	_, err := fmt.Fscanf(reader, "Public Key:\n")
	if err != nil {
		return nil, err
	}
	_, err = fmt.Fscanf(reader, "%s\n", &moduleStr)
	if err != nil {
		return nil, err
	}
	_, err = fmt.Fscanf(reader, "%s\n", &publicExponentStr)
	if err != nil {
		return nil, err
	}
	var ok bool
	var n, p *big.Int
	n, ok = big.NewInt(0).SetString(moduleStr, 10)
	if !ok {
		return nil, fmt.Errorf("invalid module")
	}
	p, ok = big.NewInt(0).SetString(publicExponentStr, 10)
	if !ok {
		return nil, fmt.Errorf("invalid publicExponent")
	}
	return NewRSAPublicKey(n, p), nil
}
