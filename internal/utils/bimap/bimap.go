package bimap

type BiMap[T comparable] struct {
	left  map[T]T
	right map[T]T
}

func NewBiMap[T comparable]() *BiMap[T] {
	return &BiMap[T]{
		left:  make(map[T]T),
		right: make(map[T]T),
	}
}

func (b *BiMap[T]) Add(left, right T) {
	b.left[left] = right
	b.right[right] = left
}

func (b *BiMap[T]) GetLeft(right T) (T, bool) {
	left, ok := b.right[right]
	return left, ok
}

func (b *BiMap[T]) GetRight(left T) (T, bool) {
	right, ok := b.left[left]
	return right, ok
}
