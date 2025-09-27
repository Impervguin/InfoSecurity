package perm

import (
	"unsafe"
)

func PermuteBlock(src uint64, permutation []uint8) (block uint64) {
	for position, n := range permutation {
		// n starts from 1 in the permutation
		n -= 1
		bit := (src >> n) & 1
		block |= bit << uint((len(permutation)-1)-position)
	}
	return
}

func RotateLeft[T ~uint8 | ~uint16 | ~uint32 | ~uint64](x T, k int) T {
	n := T(8 * unsafe.Sizeof(x))
	s := T(k) % n
	return (x << s) | (x >> (n - s))
}

func RotateRight[T ~uint8 | ~uint16 | ~uint32 | ~uint64](x T, k int) T {
	n := T(8 * unsafe.Sizeof(x))
	s := T(k) % n
	return (x >> s) | (x << (n - s))
}

func RotateLeftBase(x uint64, k int, base uint8) uint64 {
	if base > 64 {
		panic("base must be less than 64")
	}
	if base == 0 {
		return x
	}

	k = k % int(base)
	if k == 0 {
		return x
	}

	// Маска для изоляции base битов
	mask := uint64((1 << base) - 1)
	x &= mask

	// Циклический сдвиг влево
	return ((x << k) | (x >> (base - uint8(k)))) & mask
}

func RotateRightBase(x uint64, k int, base uint8) uint64 {
	if base > 64 {
		panic("base must be less than 64")
	}
	if base == 0 {
		return x
	}

	k = k % int(base)
	if k == 0 {
		return x
	}

	// Маска для изоляции base битов
	mask := uint64((1 << base) - 1)
	x &= mask

	// Циклический сдвиг вправо
	return ((x >> k) | (x << (base - uint8(k)))) & mask
}
