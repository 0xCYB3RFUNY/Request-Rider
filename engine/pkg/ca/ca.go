package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
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
	if err := m.tightenPermissions(dir); err != nil {
		return nil, err
	}

	return m, nil
}

// tightenPermissions restores 0700 on the CA directory and 0600 on the key.
//
// `GenerateCA` writes the key 0600 and `MkdirAll` makes a fresh directory 0700,
// which covers the normal case. It does not cover the case that matters: the file
// already existed and arrived with wider permissions — unpacked from an archive,
// copied from a filesystem without unix modes, or bind mounted from the host, where
// `docker-compose.yml` hands `./data/ca` over and the host decides. A readable CA
// private key means any local user can mint a certificate for any domain.
//
// Re-applying the modes on every start is idempotent and cheap, and it corrects the
// state on the next start rather than only on the next fresh install.
//
// A failure to tighten is returned rather than swallowed: the alternative is a
// silent warning that the operator never sees and a key that stays world-readable.
func (m *CAManager) tightenPermissions(dir string) error {
	if info, err := os.Stat(dir); err == nil && info.Mode().Perm() != 0700 {
		if err := os.Chmod(dir, 0700); err != nil {
			return fmt.Errorf("ca: cannot restrict directory %s: %w", dir, err)
		}
	}
	if info, err := os.Stat(m.KeyPath); err == nil && info.Mode().Perm() != 0600 {
		if err := os.Chmod(m.KeyPath, 0600); err != nil {
			return fmt.Errorf("ca: cannot restrict key %s: %w", m.KeyPath, err)
		}
	}
	return nil
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
