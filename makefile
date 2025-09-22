RSA_PUB:=./config/rsa/rsa.pub
RSA_PRI:=./config/rsa/rsa.pri
RSA_BITSIZE=2048

.PHONY: gen-rsa
gen-rsa:
	go run ./cmd/rsa/gen/main.go -b $(RSA_BITSIZE) -pri $(RSA_PRI) -pub $(RSA_PUB)

