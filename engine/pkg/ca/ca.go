package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

type CAManager struct {
	CertPath string
	KeyPath  string
	Cert     *x509.Certificate
	Key      *rsa.PrivateKey
}

func NewCAManager(dir string) (*CAManager, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	m := &CAManager{CertPath: certPath, KeyPath: keyPath}

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		if err := m.GenerateCA(); err != nil {
			return nil, err
		}
	} else {
		if err := m.LoadCA(); err != nil {
			return nil, err
		}
	}

	return m, nil
}

func (m *CAManager) GenerateCA() error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Local HTTP Lab"},
			CommonName:   "Local HTTP Lab Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	certOut, err := os.Create(m.CertPath)
	if err != nil {
		return err
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	keyOut, err := os.OpenFile(m.KeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()

	m.Cert, _ = x509.ParseCertificate(derBytes)
	m.Key = priv

	return nil
}

func (m *CAManager) LoadCA() error {
	certBytes, err := os.ReadFile(m.CertPath)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(certBytes)
	if block == nil {
		return os.ErrInvalid
	}
	m.Cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	keyBytes, err := os.ReadFile(m.KeyPath)
	if err != nil {
		return err
	}
	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil {
		return os.ErrInvalid
	}
	m.Key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return err
	}

	return nil
}
