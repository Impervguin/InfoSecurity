package bimap

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

func DumpBiMap[T comparable](b *BiMap[T], f io.StringWriter) error {
	for left, right := range b.left {
		_, err := f.WriteString(fmt.Sprintf("%v -> %v\n", left, right))
		if err != nil {
			return err
		}
	}
	return nil
}

type TransformFunc[T comparable] func(string) (T, error)

func ReadBiMap[T comparable](f io.Reader, transform TransformFunc[T]) (*BiMap[T], error) {
	b := NewBiMap[T]()
	scan := bufio.NewScanner(f)

	for scan.Scan() {
		line := scan.Text()
		line = strings.TrimSpace(line)
		parts := strings.Split(line, "->")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid line: %v", line)
		}
		left, err := transform(strings.TrimSpace(parts[0]))
		if err != nil {
			return nil, err
		}
		right, err := transform(strings.TrimSpace(parts[1]))
		if err != nil {
			return nil, err
		}
		b.Add(left, right)
	}

	return b, nil
}
