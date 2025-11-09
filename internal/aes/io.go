package aes

import "io"

func PKCS7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := make([]byte, padding)
	for i := range padText {
		padText[i] = byte(padding)
	}
	return append(data, padText...)
}

func PKCS7Unpadding(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	padding := int(data[len(data)-1])
	if padding > len(data) {
		return data
	}
	return data[:len(data)-padding]
}

func (a *AESKey) Encrypt(reader io.Reader, writer io.Writer) error {
	text, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	paddedText := PKCS7Padding(text, BlockSize)

	for i := 0; i < len(paddedText); i += BlockSize {
		block := paddedText[i : i+BlockSize]
		encryptedBlock, err := a.encryptBlock(block)
		if err != nil {
			return err
		}
		_, err = writer.Write(encryptedBlock)
		if err != nil {
			return err
		}
	}
	return nil
}

func (a *AESKey) Decrypt(reader io.Reader, writer io.Writer) error {
	text, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	decryptedText := make([]byte, 0, len(text))
	var i int
	for i = 0; i < len(text); i += BlockSize {
		block := text[i : i+BlockSize]
		decryptedBlock, err := a.decryptBlock(block)
		if err != nil {
			return err
		}
		decryptedText = append(decryptedText, decryptedBlock...)
	}
	unpaddedText := PKCS7Unpadding(decryptedText)
	_, err = writer.Write(unpaddedText)
	return err
}
