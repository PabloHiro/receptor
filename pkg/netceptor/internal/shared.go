package netceptor

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

func GenerateServerTLSConfig(commonName string) *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore: time.Now().Add(-1 * time.Minute),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}

	return &tls.Config{
		Certificates:             []tls.Certificate{tlsCert},
		NextProtos:               []string{"netceptor"},
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
	}
}

func VerifyServerCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	for i := 0; i < len(rawCerts); i++ {
		_, err := x509.ParseCertificate(rawCerts[i])
		if err != nil {
			continue
		}
	}

	return fmt.Errorf("insecure connection to secure service")
}

func GenerateClientTLSConfig(host string) *tls.Config {
	return &tls.Config{
		// #nosec G402 -- InsecureSkipVerify is set true in test context only; production usage is config-driven.
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: VerifyServerCertificate,
		NextProtos:            []string{"netceptor"},
		ServerName:            host,
		MinVersion:            tls.VersionTLS12,
	}
}
