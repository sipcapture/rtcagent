package hepclient

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"strings"
	"unicode"
)

type HEPConn struct {
	conn   net.Conn
	writer *bufio.Writer
	errCnt uint
}
type HepClient struct {
	hepQueue  chan []byte
	addr      string
	transport string
	tlsConfig *tls.Config
	client    HEPConn
}

// Option customises the behaviour of a HepClient.
type Option func(*HepClient)

// WithTLSConfig sets the TLS configuration used for the "tls" transport.
// Certificate verification is always performed unless the caller explicitly
// opts out, so the supplied configuration should normally only be used to
// provide a custom root CA or an explicit server name.
func WithTLSConfig(cfg *tls.Config) Option {
	return func(h *HepClient) {
		h.tlsConfig = cfg
	}
}

// defaultTLSConfig returns a TLS client configuration that verifies the
// server certificate chain and host name against the system trust store.
func defaultTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
}

func NewHepClient(addr, port, trans string, opts ...Option) (*HepClient, error) {

	h := &HepClient{
		addr:      strings.ToLower(cutSpace(addr + ":" + port)),
		client:    HEPConn{},
		transport: trans,
		hepQueue:  make(chan []byte, 20000),
	}

	for _, opt := range opts {
		opt(h)
	}

	if err := h.ConnectServer(); err != nil {
		return nil, fmt.Errorf("cannot establish a connection: %w", err)
	}

	go h.Start()
	return h, nil
}

func (h *HepClient) Close() {
	if err := h.client.conn.Close(); err != nil {
		log.Fatalf("cannnot close connection to %s: %v", h.addr, err)
	}
}

func (h *HepClient) ReConnect() (err error) {
	if err = h.ConnectServer(); err != nil {
		return err
	}
	h.client.writer.Reset(h.client.conn)
	return err
}

func (h *HepClient) ConnectServer() (err error) {
	var conn net.Conn

	if h.transport == "udp" {

		if conn, err = net.Dial("udp", h.addr); err != nil {
			return fmt.Errorf("dial transport failed: %s", err.Error())
		}
	} else if h.transport == "tcp" {

		if conn, err = net.Dial("tcp", h.addr); err != nil {
			return fmt.Errorf("dial transport failed: %s", err.Error())
		}
	} else if h.transport == "tls" {
		tlsConfig := h.tlsConfig
		if tlsConfig == nil {
			tlsConfig = defaultTLSConfig()
		}
		if conn, err = tls.Dial("tcp", h.addr, tlsConfig); err != nil {
			return fmt.Errorf("dial transport failed: %s", err.Error())
		}
	} else {
		return fmt.Errorf("unsupported transport: %s", h.transport)
	}

	// Only expose the connection once the dial has succeeded. Assigning the
	// result of tls.Dial directly would otherwise store a typed-nil *tls.Conn
	// inside the net.Conn interface even when the handshake fails.
	h.client.conn = conn
	h.client.writer = bufio.NewWriterSize(h.client.conn, 8192)
	return nil
}

func (h *HepClient) Output(msg []byte) {
	h.hepQueue <- msg
}

func (h *HepClient) Send(msg []byte) {
	h.client.writer.Write(msg)
	err := h.client.writer.Flush()
	if err != nil {
		log.Printf("hep flush error: %v", err)
		h.client.errCnt++
		retry := true
		if retry {
			h.client.errCnt = 0
			if err = h.ReConnect(); err != nil {
				log.Fatalf("reconnect error: %v", err)
				return
			}
		}
	}
}

func (h *HepClient) Start() {
	for msg := range h.hepQueue {
		h.Send(msg)
	}
}

func cutSpace(str string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, str)
}
