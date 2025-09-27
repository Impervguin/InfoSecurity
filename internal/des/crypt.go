package des

import (
	"encoding/binary"
	"errors"
	"io"
)

var ErrWrongEncryptedSize = errors.New("wrong encrypted size")

func (k *DESKey) Encrypt(reader io.Reader, writer io.Writer) error {
	subKeys := k.GenerateSubKeys()

	plain, err := io.ReadAll(reader)
	if err != nil {
		return err
	}

	// padding
	padding := BlockSize - (len(plain) % BlockSize)
	if padding == 0 {
		padding = BlockSize
	}
	for i := 0; i < padding; i++ {
		plain = append(plain, byte(padding))
	}

	// per-block encryption
	for i := 0; i < len(plain); i += BlockSize {
		block := binary.BigEndian.Uint64(plain[i : i+BlockSize])
		encrypted := subKeys.encryptBlock(block)
		var out [BlockSize]byte
		binary.BigEndian.PutUint64(out[:], encrypted)
		if _, err := writer.Write(out[:]); err != nil {
			return err
		}
	}
	return nil
}

func (k *DESKey) Decrypt(reader io.Reader, writer io.Writer) error {
	subKeys := k.GenerateSubKeys()

	cipher, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	if len(cipher)%BlockSize != 0 {
		return ErrWrongEncryptedSize
	}

	var plain []byte
	for i := 0; i < len(cipher); i += BlockSize {
		block := binary.BigEndian.Uint64(cipher[i : i+BlockSize])
		decrypted := subKeys.decryptBlock(block)
		var out [BlockSize]byte
		binary.BigEndian.PutUint64(out[:], decrypted)
		plain = append(plain, out[:]...)
	}

	// padding
	if len(plain) == 0 {
		return errors.New("empty plaintext")
	}
	padding := int(plain[len(plain)-1])
	if padding <= 0 || padding > BlockSize || padding > len(plain) {
		return errors.New("invalid padding")
	}
	// per-block decryption
	for i := 0; i < padding; i++ {
		if plain[len(plain)-1-i] != byte(padding) {
			return errors.New("invalid padding")
		}
	}
	plain = plain[:len(plain)-padding]

	_, err = writer.Write(plain)
	return err
}
