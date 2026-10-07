package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// CreateLocalCertificate writes a self-signed loopback certificate; never overwrites keys.
func CreateLocalCertificate(root string) error {
	dir := filepath.Join(root, "tls")
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return e
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return e
	}
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Family VPN local test only"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().AddDate(0, 0, 30), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		return e
	}
	keyBytes, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return e
	}
	for _, item := range []struct {
		name, kind string
		bytes      []byte
	}{{"local-key.pem", "PRIVATE KEY", keyBytes}, {"local-cert.pem", "CERTIFICATE", der}} {
		f, e := os.OpenFile(filepath.Join(dir, item.name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return e
		}
		e = pem.Encode(f, &pem.Block{Type: item.kind, Bytes: item.bytes})
		closeErr := f.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}
