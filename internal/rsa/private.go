package rsa

import (
	"fmt"
	"io"
	"math/big"
)

type RSAPrivateKey struct {
	Module          *big.Int
	PrivateExponent *big.Int
}

func NewRSAPrivateKey(n *big.Int, d *big.Int) *RSAPrivateKey {
	return &RSAPrivateKey{
		Module:          n,
		PrivateExponent: d,
	}
}

func (r *RSAPrivateKey) Decrypt(message []byte) ([]byte, error) {
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
		decrypted := big.NewInt(0).Exp(num, r.PrivateExponent, r.Module)
		decryptedBytes := decrypted.Bytes()

		result = append(result, decryptedBytes...)
	}

	return result, nil
}

func (r *RSAPrivateKey) Dump(reader io.Writer) error {
	_, err := fmt.Fprintf(reader, "Private Key:\n")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(reader, "%s\n", r.Module.String())
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(reader, "%s\n", r.PrivateExponent.String())
	if err != nil {
		return err
	}

	return nil
}

func Load(reader io.Reader) (*RSAPrivateKey, error) {
	var moduleStr string
	var privateExponentStr string

	_, err := fmt.Fscanf(reader, "Private Key:\n")
	if err != nil {
		return nil, err
	}
	_, err = fmt.Fscanf(reader, "%s\n", &moduleStr)
	if err != nil {
		return nil, err
	}
	_, err = fmt.Fscanf(reader, "%s\n", &privateExponentStr)
	if err != nil {
		return nil, err
	}
	var ok bool
	var n, q *big.Int
	n, ok = big.NewInt(0).SetString(moduleStr, 10)
	if !ok {
		return nil, fmt.Errorf("invalid module")
	}
	q, ok = big.NewInt(0).SetString(privateExponentStr, 10)
	if !ok {
		return nil, fmt.Errorf("invalid privateExponent")
	}

	return NewRSAPrivateKey(n, q), nil
}
