package des

import "info-security/internal/utils/perm"

var initPermutation = []uint8{
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6,
	64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17, 9, 1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7,
}

var finalPermutation = []uint8{
	40, 8, 48, 16, 56, 24, 64, 32,
	39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30,
	37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28,
	35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26,
	33, 1, 41, 9, 49, 17, 57, 25,
}

func (k *DESSubKeys) encryptBlock(block uint64) uint64 {
	var res uint64

	initBlock := perm.PermuteBlock(block, initPermutation)
	li := uint32(initBlock >> 32)
	ri := uint32(initBlock & 0x00000000FFFFFFFF)

	for i := 0; i < 16; i++ {
		nextLi := ri
		ri = li ^ feistel(ri, k.Keys[i])
		li = nextLi
	}

	res = uint64(ri)<<32 | uint64(li)

	return perm.PermuteBlock(res, finalPermutation)
}

func (k *DESSubKeys) decryptBlock(block uint64) uint64 {
	var res uint64

	initBlock := perm.PermuteBlock(block, initPermutation)
	li := uint32(initBlock >> 32)
	ri := uint32(initBlock & 0x00000000FFFFFFFF)

	for i := 0; i < 16; i++ {
		nextLi := ri
		ri = li ^ feistel(ri, k.Keys[15-i])
		li = nextLi
	}
	res = uint64(ri)<<32 | uint64(li)
	return perm.PermuteBlock(res, finalPermutation)
}

var extendPermutation = []uint8{
	32, 1, 2, 3, 4, 5,
	4, 5, 6, 7, 8, 9,
	8, 9, 10, 11, 12, 13,
	12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21,
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32, 1,
}

var pPermutation = []uint8{
	16, 7, 20, 21,
	29, 12, 28, 17,
	1, 15, 23, 26,
	5, 18, 31, 10,
	2, 8, 24, 14,
	32, 27, 3, 9,
	19, 13, 30, 6,
	22, 11, 4, 25,
}

func feistel(ri uint32, ki uint64) uint32 {
	var exri uint64 = perm.PermuteBlock(uint64(ri), extendPermutation)
	var xored uint64 = exri ^ ki
	var sRes uint32
	for i := 0; i < 8; i++ {
		bits := (xored >> (42 - i*6)) & 0x3F
		row := ((bits & 0b100000) >> 4) | (bits & 1)
		col := (bits & 0b011110) >> 1
		sRes = (sRes << 4) | uint32(sTable[i][row][col])
	}

	return uint32(perm.PermuteBlock(uint64(sRes), pPermutation))
}
