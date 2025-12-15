package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"
)

const signatureMarker = "\n---BEGIN SIMPLE SIGNATURE---\n"
const signatureEnd = "---END SIMPLE SIGNATURE---"

// ------------------ genkeys ------------------

func genKeys(dir, commonName string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	notBefore := time.Now().Add(-time.Minute)
	notAfter := time.Now().AddDate(1, 0, 0)

	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection},
		IsCA:         false,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	privPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	if err := os.WriteFile(dir+"/private.pem", privPem, 0600); err != nil {
		return err
	}

	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err := os.WriteFile(dir+"/cert.pem", certPem, 0644); err != nil {
		return err
	}

	fmt.Println("Generated keys in:", dir)
	return nil
}

// ------------------ sign ------------------

func sign(privPath, certPath, inFile, outFile string) error {
	data, err := os.ReadFile(inFile)
	if err != nil {
		return err
	}

	shaSum := sha256.Sum256(data)

	privPem, err := os.ReadFile(privPath)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(privPem)
	if block == nil {
		return fmt.Errorf("invalid private key PEM")
	}
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}

	signature, err := rsa.SignPSS(rand.Reader, privKey, crypto.SHA256, shaSum[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		return err
	}
	sigB64 := base64.StdEncoding.EncodeToString(signature)

	certPem, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}

	var sb strings.Builder
	sb.WriteString(signatureMarker)
	sb.WriteString("SIGNATURE=")
	sb.WriteString(sigB64)
	sb.WriteString("\nCERT_BEGIN\n")
	sb.Write(certPem)
	if !strings.HasSuffix(string(certPem), "\n") {
		sb.WriteString("\n")
	}
	sb.WriteString("CERT_END\n")
	sb.WriteString(signatureEnd)
	sb.WriteString("\n")

	out := append(data, []byte(sb.String())...)
	return os.WriteFile(outFile, out, 0644)
}

// ------------------ verify ------------------

func verify(signedFile string) error {
	data, err := os.ReadFile(signedFile)
	if err != nil {
		return err
	}

	parts := bytes.SplitN(data, []byte(signatureMarker), 2)
	if len(parts) != 2 {
		return fmt.Errorf("no signature block found")
	}
	content := parts[0]
	sigPart := string(parts[1])

	var sigB64, certPEM string
	scanner := bufio.NewScanner(strings.NewReader(sigPart))
	inCert := false
	var certBuf strings.Builder
	for scanner.Scan() {
		line := scanner.Text()
		if line == signatureEnd {
			break
		}
		if line == "CERT_BEGIN" {
			inCert = true
			continue
		}
		if line == "CERT_END" {
			inCert = false
			continue
		}
		if inCert {
			certBuf.WriteString(line)
			certBuf.WriteString("\n")
			continue
		}
		if strings.HasPrefix(line, "SIGNATURE=") {
			sigB64 = strings.TrimPrefix(line, "SIGNATURE=")
		}
	}
	certPEM = certBuf.String()
	if sigB64 == "" || certPEM == "" {
		return fmt.Errorf("signature block missing required fields")
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("certificate PEM parse failed")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return err
	}

	shaSum := sha256.Sum256(content)
	pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("certificate public key is not RSA")
	}
	if err := rsa.VerifyPSS(pubKey, crypto.SHA256, shaSum[:], sigBytes, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
		return fmt.Errorf("RSA-PSS verification failed: %w", err)
	}

	fmt.Printf("Signature valid.\nSigned by: %s\n", cert.Subject.CommonName)
	return nil
}

// ------------------ main ------------------

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: genkeys/sign/verify ...")
		os.Exit(2)
	}

	switch os.Args[1] {
	case "genkeys":
		if len(os.Args) != 4 {
			fmt.Println("Usage: genkeys <dir> <commonName>")
			os.Exit(2)
		}
		if err := genKeys(os.Args[2], os.Args[3]); err != nil {
			fmt.Fprintln(os.Stderr, "genkeys error:", err)
			os.Exit(1)
		}
	case "sign":
		if len(os.Args) != 6 {
			fmt.Println("Usage: sign <priv.pem> <cert.pem> <in> <out>")
			os.Exit(2)
		}
		if err := sign(os.Args[2], os.Args[3], os.Args[4], os.Args[5]); err != nil {
			fmt.Fprintln(os.Stderr, "sign error:", err)
			os.Exit(1)
		}
	case "verify":
		if len(os.Args) != 3 {
			fmt.Println("Usage: verify <signedfile>")
			os.Exit(2)
		}
		if err := verify(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, "verify error:", err)
			os.Exit(1)
		}
	default:
		fmt.Println("Unknown command")
		os.Exit(2)
	}
}
