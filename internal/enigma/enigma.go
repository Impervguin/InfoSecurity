package enigma

import "fmt"

type EnigmaMachine struct {
	part EnigmaPart
}

func NewEnigmaMachine(part EnigmaPart) *EnigmaMachine {
	return &EnigmaMachine{
		part: part,
	}
}

func (m *EnigmaMachine) Apply(data []byte) ([]byte, error) {
	var result []byte
	for _, b := range data {
		r, err := m.part.Apply(b)
		if err != nil {
			return nil, fmt.Errorf("error applying part: %w", err)
		}
		result = append(result, r)
		m.part.Update()
	}
	return result, nil
}
