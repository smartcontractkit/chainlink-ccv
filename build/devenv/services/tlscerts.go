package services

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

type TLSCertPaths struct {
	CACertFile     string
	ServerCertFile string
	ServerKeyFile  string
}

func GenerateTLSCertificates(hostnames []string, outputDir string) (*TLSCertPaths, error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	caKey, caCert, caCertPEM, err := generateCA()
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA: %w", err)
	}

	serverCertPEM, serverKeyPEM, err := generateServerCert(caKey, caCert, hostnames)
	if err != nil {
		return nil, fmt.Errorf("failed to generate server certificate: %w", err)
	}

	paths := &TLSCertPaths{
		CACertFile:     filepath.Join(outputDir, "ca.crt"),
		ServerCertFile: filepath.Join(outputDir, "server.crt"),
		ServerKeyFile:  filepath.Join(outputDir, "server.key"),
	}

	if err := os.WriteFile(paths.CACertFile, caCertPEM, 0o644); err != nil {
		return nil, fmt.Errorf("failed to write CA cert: %w", err)
	}

	if err := os.WriteFile(paths.ServerCertFile, serverCertPEM, 0o644); err != nil {
		return nil, fmt.Errorf("failed to write server cert: %w", err)
	}

	if err := os.WriteFile(paths.ServerKeyFile, serverKeyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("failed to write server key: %w", err)
	}

	return paths, nil
}

func generateCA() (*ecdsa.PrivateKey, *x509.Certificate, []byte, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate CA key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"CCV DevEnv CA"},
			CommonName:   "CCV DevEnv Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	caCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertDER,
	})

	return caKey, caCert, caCertPEM, nil
}

func generateServerCert(caKey *ecdsa.PrivateKey, caCert *x509.Certificate, hostnames []string) (certPEM, keyPEM []byte, err error) {
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate server key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	serverTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"CCV DevEnv"},
			CommonName:   hostnames[0],
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    hostnames,
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create server certificate: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: serverCertDER,
	})

	serverKeyDER, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal server key: %w", err)
	}

	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: serverKeyDER,
	})

	return certPEM, keyPEM, nil
}
