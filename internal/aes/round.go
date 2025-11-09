package aes

func (a *AESKey) keyExpansion() [][]byte {
	nk := a.KeySize() / 4
	nr := nk + 6

	roundKeys := make([][]byte, nr+1)
	for i := range roundKeys {
		roundKeys[i] = make([]byte, BlockSize)
	}

	copy(roundKeys[0], a.key)

	for i := 1; i <= nr; i++ {
		prevKey := roundKeys[i-1]
		currentKey := roundKeys[i]

		temp := make([]byte, 4)
		copy(temp, prevKey[BlockSize-4:BlockSize])
		temp = subWord(rotWord(temp))
		temp[0] ^= byte(rcon[i] >> 24)

		for j := 0; j < 4; j++ {
			currentKey[j] = prevKey[j] ^ temp[j]
		}

		for j := 4; j < BlockSize; j++ {
			currentKey[j] = currentKey[j-4] ^ prevKey[j]
		}
	}
	return roundKeys
}

func rotWord(word []byte) []byte {
	return []byte{word[1], word[2], word[3], word[0]}
}

func subWord(word []byte) []byte {
	result := make([]byte, 4)
	for i := 0; i < 4; i++ {
		result[i] = sBox[word[i]]
	}
	return result
}
