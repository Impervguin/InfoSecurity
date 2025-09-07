package map_io

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func DumpMap[T comparable](b map[T]T, fName string) error {
	f, err := os.OpenFile(fName, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	for left, right := range b {
		_, err = f.WriteString(fmt.Sprintf("%v -> %v\n", left, right))
		if err != nil {
			return err
		}
	}
	return nil
}

type TransformFunc[T comparable] func(string) (T, error)

func ReadMap[T comparable](fName string, transform TransformFunc[T]) (map[T]T, error) {
	b := make(map[T]T)
	f, err := os.Open(fName)
	if err != nil {
		return nil, err
	}
	defer f.Close()

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
		b[left] = right
	}

	return b, nil
}
