package ipc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	certFile = "ipc-server.crt"
	keyFile  = "ipc-server.key"
)

// certPaths returns the cert and key paths for the given directory.
func certPaths(dir string) (string, string) {
	return filepath.Join(dir, certFile), filepath.Join(dir, keyFile)
}

// ensureServerCert loads the TLS cert+key from dir, generating them if absent.
func ensureServerCert(dir string) (*tls.Certificate, *x509.Certificate, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, nil, fmt.Errorf("failed to create cert dir: %w", err)
	}

	crtPath, keyPath := certPaths(dir)

	// Try loading existing cert first.
	if _, err := os.Stat(crtPath); err == nil {
		cert, err := tls.LoadX509KeyPair(crtPath, keyPath)
		if err == nil {
			leaf, err := x509.ParseCertificate(cert.Certificate[0])
			if err == nil {
				return &cert, leaf, nil
			}
		}
		// Fall through to regeneration if load or parse fails.
	}

	return generateSelfSignedCert(dir)
}

// generateSelfSignedCert generates a self-signed TLS cert for loopback IPC.
// The cert is valid for 10 years and bound to 127.0.0.1/::1.
func generateSelfSignedCert(dir string) (*tls.Certificate, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("key generation failed: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("serial generation failed: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"AfterDark Systems"},
			CommonName:   "afterdark-darkd IPC",
		},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
		NotBefore:             time.Now().Add(-time.Minute), // small grace for clock skew
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("cert creation failed: %w", err)
	}

	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("cert parse failed: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("key marshal failed: %w", err)
	}

	crtPath, keyPath := certPaths(dir)

	if err := os.WriteFile(crtPath, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}), 0644); err != nil {
		return nil, nil, fmt.Errorf("failed to write cert: %w", err)
	}

	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	}), 0600); err != nil {
		return nil, nil, fmt.Errorf("failed to write key: %w", err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
		Leaf:        leaf,
	}
	return &tlsCert, leaf, nil
}

// loadClientTLSConfig loads the server cert as a trusted CA for the client.
func loadClientTLSConfig(dir string) (*tls.Config, error) {
	crtPath, _ := certPaths(dir)
	pemData, err := os.ReadFile(crtPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read IPC server cert %s: %w", crtPath, err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, fmt.Errorf("failed to parse IPC server cert")
	}

	return &tls.Config{
		RootCAs:    pool,
		ServerName: "127.0.0.1",
		MinVersion: tls.VersionTLS13,
	}, nil
}
