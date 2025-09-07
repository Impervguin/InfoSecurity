package enigma

type EnigmaPart interface {
	Apply(data byte) (byte, error)
	Update()
}

type MiddleEnigmaPart interface {
	EnigmaPart
	After(part EnigmaPart)
}
