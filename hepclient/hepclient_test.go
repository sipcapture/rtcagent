package hepclient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
)

// testCA generates a throw-away CA certificate and returns it together with its
// key and the PEM encoding used to build a client trust store.
func testCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "rtcagent test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return cert, key, pemBytes
}

// testServerCertificate issues a server certificate for 127.0.0.1 signed by ca.
func testServerCertificate(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create server certificate: %v", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{der, ca.Raw},
		PrivateKey:  key,
	}
}

// startTLSServer starts a TLS listener on the loopback interface and returns its
// address. The listener is closed automatically when the test finishes.
func startTLSServer(t *testing.T, cert tls.Certificate) string {
	t.Helper()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
			}(conn)
		}
	}()

	return ln.Addr().String()
}

func TestDefaultTLSConfigVerifiesCertificates(t *testing.T) {
	cfg := defaultTLSConfig()
	if cfg.InsecureSkipVerify {
		t.Fatal("default TLS config must verify server certificates")
	}
	if cfg.MinVersion < tls.VersionTLS12 {
		t.Fatalf("unexpected minimum TLS version: %#x", cfg.MinVersion)
	}
}

func TestConnectServerTLSRejectsUntrustedCertificate(t *testing.T) {
	ca, caKey, _ := testCA(t)
	addr := startTLSServer(t, testServerCertificate(t, ca, caKey))

	h := &HepClient{addr: addr, transport: "tls"}

	if err := h.ConnectServer(); err == nil {
		_ = h.client.conn.Close()
		t.Fatal("expected TLS dial to fail for an untrusted certificate")
	}

	if h.client.conn != nil {
		t.Fatal("connection must not be established when verification fails")
	}
}

func TestConnectServerTLSAcceptsTrustedCertificate(t *testing.T) {
	ca, caKey, caPEM := testCA(t)
	addr := startTLSServer(t, testServerCertificate(t, ca, caKey))

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("failed to build test trust store")
	}

	h := &HepClient{
		addr:      addr,
		transport: "tls",
		tlsConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool},
	}

	if err := h.ConnectServer(); err != nil {
		t.Fatalf("expected TLS dial to succeed with a trusted CA: %v", err)
	}
	_ = h.client.conn.Close()
}

func TestNewHepClientTLSWithCustomCA(t *testing.T) {
	ca, caKey, caPEM := testCA(t)
	addr := startTLSServer(t, testServerCertificate(t, ca, caKey))

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("failed to build test trust store")
	}

	h, err := NewHepClient(host, port, "tls",
		WithTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}))
	if err != nil {
		t.Fatalf("NewHepClient: %v", err)
	}
	h.Close()
}

func TestNewHepClientTLSRejectsUntrustedCertificate(t *testing.T) {
	ca, caKey, _ := testCA(t)
	addr := startTLSServer(t, testServerCertificate(t, ca, caKey))

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}

	if _, err := NewHepClient(host, port, "tls"); err == nil {
		t.Fatal("expected NewHepClient to fail for an untrusted certificate")
	}
}

func TestConnectServerUnsupportedTransport(t *testing.T) {
	h := &HepClient{addr: "127.0.0.1:9060", transport: "sctp"}

	if err := h.ConnectServer(); err == nil {
		_ = h.client.conn.Close()
		t.Fatal("expected unsupported transport to return an error")
	}
}
