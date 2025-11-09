package aes

import "fmt"

func subBytes(state []byte) {
	for i := 0; i < BlockSize; i++ {
		state[i] = sBox[state[i]]
	}
}

func invSubBytes(state []byte) {
	for i := 0; i < BlockSize; i++ {
		state[i] = invSBox[state[i]]
	}
}

func shiftRows(state []byte) {
	state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]

	state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]

	state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]
}

func invShiftRows(state []byte) {
	state[1], state[5], state[9], state[13] = state[13], state[1], state[5], state[9]
	state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
	state[3], state[7], state[11], state[15] = state[7], state[11], state[15], state[3]
}

func galoisMultiply(a, b byte) byte {
	var p byte
	var hiBitSet byte

	for i := 0; i < 8; i++ {
		if (b & 1) == 1 {
			p ^= a
		}

		hiBitSet = a & 0x80
		a <<= 1
		if hiBitSet == 0x80 {
			a ^= 0x1b
		}
		b >>= 1
	}

	return p
}

func mixColumns(state []byte) {
	for i := 0; i < 4; i++ {
		col := state[i*4 : i*4+4]
		a := make([]byte, 4)
		b := make([]byte, 4)

		for j := 0; j < 4; j++ {
			a[j] = col[j]
			b[j] = col[j] & 0x80
			if b[j] == 0x80 {
				b[j] = (col[j] << 1) ^ 0x1b
			} else {
				b[j] = col[j] << 1
			}
		}

		col[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]
		col[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]
		col[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]
		col[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]
	}
}

func invMixColumns(state []byte) {
	for i := 0; i < 4; i++ {
		col := state[i*4 : i*4+4]

		a := make([]byte, 4)
		for j := 0; j < 4; j++ {
			a[j] = col[j]
		}

		col[0] = galoisMultiply(a[0], 0x0e) ^ galoisMultiply(a[1], 0x0b) ^
			galoisMultiply(a[2], 0x0d) ^ galoisMultiply(a[3], 0x09)
		col[1] = galoisMultiply(a[0], 0x09) ^ galoisMultiply(a[1], 0x0e) ^
			galoisMultiply(a[2], 0x0b) ^ galoisMultiply(a[3], 0x0d)
		col[2] = galoisMultiply(a[0], 0x0d) ^ galoisMultiply(a[1], 0x09) ^
			galoisMultiply(a[2], 0x0e) ^ galoisMultiply(a[3], 0x0b)
		col[3] = galoisMultiply(a[0], 0x0b) ^ galoisMultiply(a[1], 0x0d) ^
			galoisMultiply(a[2], 0x09) ^ galoisMultiply(a[3], 0x0e)
	}
}

func addRoundKey(state, roundKey []byte) {
	for i := 0; i < BlockSize; i++ {
		state[i] ^= roundKey[i]
	}
}

func (a *AESKey) encryptBlock(block []byte) ([]byte, error) {
	if len(block) != BlockSize {
		return nil, fmt.Errorf("invalid block size")
	}
	state := make([]byte, BlockSize)
	copy(state, block)

	nr := len(a.roundKeys) - 1

	addRoundKey(state, a.roundKeys[0])
	for round := 1; round <= nr-1; round++ {
		subBytes(state)
		shiftRows(state)
		mixColumns(state)
		addRoundKey(state, a.roundKeys[round])
	}
	subBytes(state)
	shiftRows(state)
	addRoundKey(state, a.roundKeys[nr])
	return state, nil
}

func (a *AESKey) decryptBlock(block []byte) ([]byte, error) {
	if len(block) != BlockSize {
		return nil, fmt.Errorf("invalid block size")
	}
	state := make([]byte, BlockSize)
	copy(state, block)

	nr := len(a.roundKeys) - 1

	addRoundKey(state, a.roundKeys[nr])
	for round := nr - 1; round > 0; round-- {
		invShiftRows(state)
		invSubBytes(state)
		addRoundKey(state, a.roundKeys[round])
		invMixColumns(state)
	}
	invShiftRows(state)
	invSubBytes(state)
	addRoundKey(state, a.roundKeys[0])
	return state, nil
}
