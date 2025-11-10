package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const signatureMarker = "\n---BEGIN SIMPLE SIGNATURE---\n"

func usage() {
	fmt.Println(`Usage:
  sign  <username> <password> <input> <output>   sign simple signature into file
  verify <username> <password> <signedfile>       Verify simple signature in file`)
}

// sign appends a signature block to the file
func sign(username, password, inputFile, outputFile string) error {
	data, err := os.ReadFile(inputFile)
	if err != nil {
		return err
	}

	// bcrypt hash of password
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	timestamp := time.Now().Format(time.RFC3339)
	signatureBlock := fmt.Sprintf("%sUSER=%s\nTIME=%s\nPASSHASH=%s\n---END SIMPLE SIGNATURE---\n",
		signatureMarker, username, timestamp, base64.StdEncoding.EncodeToString(hashed))

	out := append(data, []byte(signatureBlock)...)
	return os.WriteFile(outputFile, out, 0644)
}

// verify compares provided password with stored hash
func verify(username, password, signedFile string) error {
	data, err := os.ReadFile(signedFile)
	if err != nil {
		return err
	}

	// split content and signature
	parts := bytes.SplitN(data, []byte(signatureMarker), 2)
	if len(parts) != 2 {
		return fmt.Errorf("no signature block found")
	}

	sigPart := string(parts[1])
	scanner := bufio.NewScanner(strings.NewReader(sigPart))

	var sigUser, sigTime, sigHash string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "USER=") {
			sigUser = strings.TrimPrefix(line, "USER=")
		} else if strings.HasPrefix(line, "TIME=") {
			sigTime = strings.TrimPrefix(line, "TIME=")
		} else if strings.HasPrefix(line, "PASSHASH=") {
			sigHash = strings.TrimPrefix(line, "PASSHASH=")
		}
	}

	if sigUser == "" || sigHash == "" {
		return fmt.Errorf("invalid signature format")
	}
	if sigUser != username {
		return fmt.Errorf("username mismatch: expected %s, got %s", username, sigUser)
	}

	hashedBytes, err := base64.StdEncoding.DecodeString(sigHash)
	if err != nil {
		return fmt.Errorf("bad encoding in signature: %v", err)
	}

	// bcrypt comparison
	if err := bcrypt.CompareHashAndPassword(hashedBytes, []byte(password)); err != nil {
		return fmt.Errorf("signature invalid (wrong password)")
	}

	fmt.Printf("Signature valid.\nSigned by: %s at %s\n", sigUser, sigTime)
	return nil
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "sign":
		if len(os.Args) != 6 {
			usage()
			os.Exit(2)
		}
		if err := sign(os.Args[2], os.Args[3], os.Args[4], os.Args[5]); err != nil {
			fmt.Println("Error:", err)
			os.Exit(1)
		}
		fmt.Println("File signed successfully (simple signature signded).")

	case "verify":
		if len(os.Args) != 5 {
			usage()
			os.Exit(2)
		}
		if err := verify(os.Args[2], os.Args[3], os.Args[4]); err != nil {
			fmt.Println("Error:", err)
			os.Exit(1)
		}

	default:
		usage()
		os.Exit(2)
	}
}
